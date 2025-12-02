# .openpipes/scripts/lib/safe_runner.sh
# Wrapper que ENVOLVE módulos existentes SEM MODIFICÁ-LOS

safe_run() {
    local script="$1"
    shift
    local args="$@"
    local max_retries=3
    local attempt=1
    
    while [ $attempt -le $max_retries ]; do
        # Executa o script ORIGINAL sem alterá-lo
        if timeout 3600 "$script" $args; then
            return 0
        else
            local exit_code=$?
            echo "[RETRY] $script failed (exit $exit_code). Attempt $attempt/$max_retries"
            attempt=$((attempt + 1))
            sleep $((2 ** attempt))  # backoff exponencial
        fi
    done
    
    echo "[CRITICAL] $script failed after $max_retries attempts"
    return 1
}

# Usage no orchestrator (NÃO altera os módulos):
# safe_run ./recon.sh example.com
# safe_run ./nwrapper.sh 192.168.1.1