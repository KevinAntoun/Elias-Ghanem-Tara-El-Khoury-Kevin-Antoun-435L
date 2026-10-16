"""Launch nine local Flask development processes (not a production runner)."""

import subprocess
import sys

from shared.config import PROJECT_ROOT, SERVICE_PORTS, service_port


def main() -> int:
    processes = []
    try:
        print("Starting Flask services (Ctrl+C to stop all):", flush=True)
        for service in SERVICE_PORTS:
            process = subprocess.Popen(
                [sys.executable, "-m", f"services.{service}.app"],
                cwd=str(PROJECT_ROOT),
            )
            processes.append(process)
            print(f"  {service:<17} http://127.0.0.1:{service_port(service)}/health", flush=True)
        for process in processes:
            if process.wait() != 0:
                print("A service exited unexpectedly. Stopping remaining services.", file=sys.stderr)
                return 1
    except KeyboardInterrupt:
        print("\nStopping services...", flush=True)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
