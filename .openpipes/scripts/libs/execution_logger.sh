# .openpipes/scripts/lib/execution_logger.sh
# Captura stdout/stderr dos módulos SEM MODIFICÁ-LOS

log_execution() {
    local module="$1"
    shift
    local args="$@"
    local log_file=".openpipes/logs/$(date +'%Y%m%d')_${module}.log"
    local start_time=$(date +%s)
    
    {
        echo "=== START: $module at $(date) ==="
        echo "Arguments: $args"
        echo "---"
        
        # Executa o módulo ORIGINAL, apenas capturando output
        "$module" $args 2>&1
        
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        echo "---"
        echo "=== END: exit=$exit_code duration=${duration}s ==="
    } | tee -a "$log_file"
    
    return $exit_code
}

# Usage:
# log_execution ./nuclei-runner.sh example.com.md