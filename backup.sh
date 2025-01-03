#!/bin/bash

set -eo pipefail

# Configuration
declare -A CONFIG=(
    [REPLICA_NODE_HOST]="${REPLICA_NODE_HOST}"         # Replica node hostname
    [MONGODB_USER]="${MONGODB_ROOT_USER}"             # MongoDB user
    [MONGODB_PWD]="${MONGODB_ROOT_PASSWORD}"          # MongoDB password
    [S3_BUCKET]="${S3_BUCKET_NAME}"                   # S3 bucket name for backups
    [ARCHIVE_BUCKET]="${ARCHIVE_S3_BUCKET}"           # S3 bucket for archiving full backups
    [S3_REGION]="${S3_BUCKET_REGION}"                 # S3 region
    [OUTPUT_DIR]="${OUTPUT_DIRECTORY:-/tmp/backups}"  # Local output directory for backups
    [RETAIN_ITERATIONS]="${RETAIN_ITERATIONS:-2}"     # Number of full backups to retain
    [FULL_BACKUP_DAYS]="${FULL_BACKUP_DAYS:-1,7}"     # Days of the week for full backups
    [FULL_BACKUP_TIME]="${FULL_BACKUP_TIME:-02:00}"   # Time (UTC) for full backups
    [COMPRESSION_THREADS]="${COMPRESSION_THREADS:-4}" # Threads for compression
)

# Logging utility
log() {
    local level=$1
    local message=$2
    echo "$(date -u '+%Y-%m-%dT%H:%M:%S') [$level] $message" >&2
}

# Validate environment dependencies
validate_environment() {
    log "INFO" "Validating environment..."
    local tools=("aws" "mongodump" "bsondump" "jq" "tar" "gzip" "sha256sum" "du" "pigz")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            log "ERROR" "Required tool $tool is not installed or not in PATH."
            exit 1
        fi
    done

    if [[ -z "${CONFIG[REPLICA_NODE_HOST]}" || -z "${CONFIG[MONGODB_USER]}" || -z "${CONFIG[MONGODB_PWD]}" || -z "${CONFIG[S3_BUCKET]}" ]]; then
        log "ERROR" "Missing required environment variables."
        exit 1
    fi

    log "INFO" "Environment validation successful."
}

# Acquire lock to prevent concurrent backups
acquire_lock() {
    local lock_file="s3://${CONFIG[S3_BUCKET]}/mongo_backup.lock"
    if aws s3api head-object --bucket "${CONFIG[S3_BUCKET]}" --key "mongo_backup.lock" --region "${CONFIG[S3_REGION]}" >/dev/null 2>&1; then
        log "ERROR" "Another instance of the backup script is already running. Exiting."
        exit 1
    fi
    echo "LOCKED" | aws s3 cp - "$lock_file" --region "${CONFIG[S3_REGION]}"
    trap "release_lock" EXIT
}

# Release the lock after backup completes
release_lock() {
    local lock_file="s3://${CONFIG[S3_BUCKET]}/mongo_backup.lock"
    aws s3 rm "$lock_file" --region "${CONFIG[S3_REGION]}" || log "WARN" "Failed to remove lock."
}

# Validate checksum of a file
validate_checksum() {
    local file="$1"
    local expected_checksum="$2"

    log "INFO" "Validating checksum for $file..."
    local actual_checksum
    actual_checksum=$(sha256sum "$file" | awk '{print $1}')
    if [[ "$actual_checksum" != "$expected_checksum" ]]; then
        log "ERROR" "Checksum mismatch for $file. Expected: $expected_checksum, Got: $actual_checksum"
        exit 1
    fi
    log "INFO" "Checksum validation successful for $file."
}

# Execute a command with retries
execute_with_retry() {
    local cmd="$1"
    local retries=3
    local count=0
    until $cmd; do
        count=$((count + 1))
        if [[ $count -ge $retries ]]; then
            log "ERROR" "Command failed after $retries attempts: $cmd"
            exit 1
        fi
        log "WARN" "Command failed. Retrying ($count/$retries)..."
        sleep 5
    done
}


# Determine if a full backup is needed
is_full_backup_needed() {
    local current_day=$(date -u +%u)
    local current_time=$(date -u +%H:%M)
    IFS=',' read -ra backup_days <<< "${CONFIG[FULL_BACKUP_DAYS]}"
    for day in "${backup_days[@]}"; do
        if [[ "$current_day" -eq "$day" && "$current_time" == "${CONFIG[FULL_BACKUP_TIME]}" ]]; then
            return 0
        fi
    done
    return 1
}

# Check if an existing full backup is present
has_existing_full_backup() {
    log "INFO" "Checking for existing full backups..."
    aws s3api list-objects --bucket "${CONFIG[S3_BUCKET]}" \
        --region "${CONFIG[S3_REGION]}" \
        --query "Contents[?contains(Key, \`full-backup\`)]" \
        --output text >/dev/null 2>&1
}

# Cleanup old backups
cleanup_old_backups() {
    log "INFO" "Cleaning up old backups from ${CONFIG[S3_BUCKET]}..."
    local full_backups
    full_backups=$(aws s3api list-objects \
        --bucket "${CONFIG[S3_BUCKET]}" \
        --region "${CONFIG[S3_REGION]}" \
        --query "sort_by(Contents[?contains(Key, \`full-backup\`)], &LastModified)[].Key" \
        --output text)

    local retained_full_backups
    retained_full_backups=$(echo "$full_backups" | tail -n "${CONFIG[RETAIN_ITERATIONS]}")

    local backups_to_delete
    backups_to_delete=$(echo "$full_backups" | grep -v -F "$retained_full_backups")

    for backup in $backups_to_delete; do
        log "INFO" "Deleting full backup: $backup"
        aws s3 rm "s3://${CONFIG[S3_BUCKET]}/$backup" --region "${CONFIG[S3_REGION]}"
    done
}

# Archive weekly full backups
archive_weekly_full_backups() {
    log "INFO" "Archiving weekly full backups..."
    local full_backups
    full_backups=$(aws s3api list-objects \
        --bucket "${CONFIG[S3_BUCKET]}" \
        --region "${CONFIG[S3_REGION]}" \
        --query "Contents[?contains(Key, \`full-backup\`)].Key" \
        --output text)

    for backup in $full_backups; do
        log "INFO" "Archiving full backup: $backup"
        aws s3 cp "s3://${CONFIG[S3_BUCKET]}/$backup" \
            "s3://${CONFIG[ARCHIVE_BUCKET]}/$backup" \
            --region "${CONFIG[S3_REGION]}"
    done
}

cleanup_temp_files() {
    local compressed_file=$1
    local uncompressed_dir=$2

    log "INFO" "Cleaning up temporary files..."

    # Remove the compressed file
    if [[ -f "$compressed_file" ]]; then
        rm -f "$compressed_file"
        log "INFO" "Deleted compressed file: $compressed_file"
    fi

    # Remove all uncompressed files
    find "$uncompressed_dir" -type f -name "*.bson" -or -name "*.metadata.json" -delete
    log "INFO" "Deleted uncompressed files from: $uncompressed_dir"
}


fetch_last_backup_from_s3() {
    log "INFO" "Fetching the latest backup from S3..."

    # Find the latest backup file in S3
    local latest_backup
    latest_backup=$(aws s3api list-objects \
        --bucket "${CONFIG[S3_BUCKET]}" \
        --region "${CONFIG[S3_REGION]}" \
        --query "sort_by(Contents[?contains(Key, \`tar.gz\`)], &LastModified)[-1].Key" \
        --output text)

    if [[ -z "$latest_backup" || "$latest_backup" == "None" ]]; then
        log "WARN" "No previous backup found in S3."
        return 1
    fi

    log "INFO" "Downloading latest backup file: $latest_backup..."
    local backup_path="${CONFIG[OUTPUT_DIR]}/${latest_backup##*/}"
    aws s3 cp "s3://${CONFIG[S3_BUCKET]}/$latest_backup" "$backup_path" --region "${CONFIG[S3_REGION]}"

    log "INFO" "Uncompressing the backup file..."
    tar -xzf "$backup_path" -C "${CONFIG[OUTPUT_DIR]}"

    # Check if oplog.bson exists
    if [[ ! -f "${CONFIG[OUTPUT_DIR]}/oplog.bson" ]]; then
        log "ERROR" "oplog.bson file not found after uncompressing the backup."
        rm -f "$backup_path" # Cleanup the tar.gz file
        return 1
    fi

    # Extract the last timestamp from the oplog
    log "INFO" "Extracting the last timestamp from oplog.bson..."
    local last_ts
    last_ts=$(bsondump "${CONFIG[OUTPUT_DIR]}/oplog.bson" | grep ts | tail -1 | jq -r '.ts')
    if [[ -z "$last_ts" ]]; then
        log "ERROR" "Failed to extract last timestamp from oplog.bson."
        cleanup_temp_files "$backup_path" "${CONFIG[OUTPUT_DIR]}"
        return 1
    fi

    log "INFO" "Last oplog timestamp: $last_ts"

    # Cleanup all temporary files
    cleanup_temp_files "$backup_path" "${CONFIG[OUTPUT_DIR]}"

    echo "$last_ts"
    return 0
}

perform_incremental_backup() {
    log "INFO" "Performing incremental backup..."

    # Fetch and extract the last timestamp from the oplog
    local last_ts
    last_ts=$(fetch_last_backup_from_s3)
    if [[ $? -ne 0 || -z "$last_ts" ]]; then
        log "WARN" "No valid last timestamp found. Switching to full backup."
        perform_full_backup
        return
    fi

    log "INFO" "Using last timestamp: $last_ts for incremental backup."

    # Perform the incremental backup
    mongodump --host "${CONFIG[REPLICA_NODE_HOST]}" \
              --username "${CONFIG[MONGODB_USER]}" \
              --password "${CONFIG[MONGODB_PWD]}" \
              --authenticationDatabase admin \
              --db local --collection oplog.rs \
              --query "{\"ts\": {\"\$gt\": $last_ts}}" \
              --out "${CONFIG[OUTPUT_DIR]}"
}

# Perform a full backup
perform_full_backup() {
    log "INFO" "Performing full backup..."
    mongodump --host "${CONFIG[REPLICA_NODE_HOST]}" \
              --username "${CONFIG[MONGODB_USER]}" \
              --password "${CONFIG[MONGODB_PWD]}" \
              --authenticationDatabase admin \
              --readPreference secondaryPreferred \
              --oplog \
              --out "${CONFIG[OUTPUT_DIR]}"
}


# Compress backup
compress_backup() {
    local input_dir="$1"
    local output_file="$2"
    tar -cf - -C "$input_dir" . | pigz -p "${CONFIG[COMPRESSION_THREADS]}" > "$output_file"
}

# Generate metadata
generate_metadata() {
    local file_path="$1"
    local metadata_file="${file_path}.metadata"
    echo "Backup File: $(basename "$file_path")" > "$metadata_file"
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$metadata_file"
    echo "Checksum: $(sha256sum "$file_path" | awk '{print $1}')" >> "$metadata_file"
    echo "Size: $(du -h "$file_path" | awk '{print $1}')" >> "$metadata_file"
    log "INFO" "Generated metadata for $file_path: $metadata_file"
}

upload_backup_with_metadata() {
    local backup_file="$1"

    # Generate metadata
    local metadata_file="${backup_file}.metadata"
    generate_metadata "$backup_file"

    # Upload backup file to S3
    log "INFO" "Uploading backup file to S3: $backup_file"
    aws s3 cp "$backup_file" "s3://${CONFIG[S3_BUCKET]}/$(basename "$backup_file")" --region "${CONFIG[S3_REGION]}"

    # Upload metadata file to S3
    log "INFO" "Uploading metadata file to S3: $metadata_file"
    aws s3 cp "$metadata_file" "s3://${CONFIG[S3_BUCKET]}/$(basename "$metadata_file")" --region "${CONFIG[S3_REGION]}"

    log "INFO" "Backup and metadata uploaded successfully."
}



# Main function
main() {
    validate_environment
    #acquire_lock

    log "INFO" "Starting MongoDB backup process..."
    local backup_type="incremental"


    # Start the timer
    local start_time=$(date +%s)

    if ! has_existing_full_backup || is_full_backup_needed; then
        backup_type="full"
        perform_full_backup
        archive_weekly_full_backups
        #cleanup_old_backups
    else
        perform_incremental_backup
    fi

    local timestamp=$(date -u +%Y%m%d_%H%M%S)
    local backup_file="${CONFIG[OUTPUT_DIR]}/${timestamp}_${backup_type}-backup.tar.gz"

    # Compress the backup
    compress_backup "${CONFIG[OUTPUT_DIR]}" "$backup_file"
    log "INFO" "Backup compressed: $backup_file"

    # Upload backup with metadata
    upload_backup_with_metadata "$backup_file"

    release_lock

    # End the timer and calculate the elapsed time
    local end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    log "INFO" "Backup process completed in $elapsed_time seconds."
}


main "$@"
