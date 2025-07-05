import subprocess
import json
import logging
import os

# Relative import for config within the xenon package
from ..config import WARP_PY_PATH, python_executable

logger = logging.getLogger(__name__)

def generate_warp_config_external():
    """
    Runs the external assets/warp.py script to generate a Warp outbound config.
    Returns the parsed JSON config as a Python dict, or None on error tuple (None, error_message).
    """
    # WARP_PY_PATH should point to xenon_project/assets/warp.py
    # This script (xenon/tools/warp.py) is calling the one in assets.
    # This can be confusing. The long-term plan should be to integrate the logic
    # of assets/warp.py directly into this function, making WARP_PY_PATH obsolete.
    # For now, we proceed with calling the external script.

    if not os.path.exists(WARP_PY_PATH):
        logger.error(f"Warp generation script not found at: {WARP_PY_PATH}")
        return None, f"Warp script not found at {WARP_PY_PATH}"

    # Ensure the script is executable by the user running Flask app
    # This might require sudo if Flask runs as non-root and script needs root.
    # However, assets/warp.py itself doesn't seem to require root, only wgcf does,
    # and wgcf is usually downloaded to a place where it can be run.
    # The original assets/warp.py chmod's its downloaded wgcf.
    if not os.access(WARP_PY_PATH, os.X_OK):
        try:
            # Try to make it executable. This might fail due to permissions.
            os.chmod(WARP_PY_PATH, os.stat(WARP_PY_PATH).st_mode | 0o111) # Add ugo+x
            logger.info(f"Made Warp script executable: {WARP_PY_PATH}")
        except OSError as e:
            logger.error(f"Failed to make Warp script {WARP_PY_PATH} executable: {e}. Please check permissions.")
            # If chmod fails, it's a strong indicator the subprocess call will also fail.
            return None, f"Warp script at {WARP_PY_PATH} is not executable and chmod failed."


    command_to_run = [python_executable, WARP_PY_PATH]
    logger.info(f"Executing Warp generation script: {' '.join(command_to_run)}")

    try:
        result = subprocess.run(
            command_to_run,
            capture_output=True,
            text=True,
            check=True,
            timeout=180 # Increased timeout as it involves downloads and wgcf execution
        )

        output_str = result.stdout.strip()
        if not output_str: # Handle empty output case
            logger.error(f"Warp script at {WARP_PY_PATH} produced no output.")
            return None, "Warp script produced no output."

        logger.debug(f"Warp script raw output: {output_str}")

        config_dict = json.loads(output_str)
        logger.info("Successfully generated and parsed Warp configuration using external script.")
        return config_dict, None

    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() if e.stderr else e.stdout.strip() # Prefer stderr
        logger.error(f"Warp script execution failed. Return code: {e.returncode}. Output: '{error_output}'")
        # Attempt to parse error_output as JSON, as assets/warp.py might output structured errors
        try:
            err_json = json.loads(error_output)
            if "error" in err_json: # Assuming a simple {"error": "message"} structure
                return None, f"Warp script error: {err_json['error']}"
        except json.JSONDecodeError:
            # Not a JSON error, use the raw error_output, ensuring it's not too long.
            pass
        return None, f"Warp script failed: {error_output[:500] or 'No specific error message.'}" # Truncate long errors
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout expired while running Warp script: {WARP_PY_PATH}")
        return None, "Timeout generating Warp configuration."
    except json.JSONDecodeError as e:
        # This error means this script (tools/warp.py) failed to parse output of assets/warp.py
        logger.error(f"Failed to parse JSON output from Warp script: {e}. Output was: '{result.stdout.strip() if 'result' in locals() else 'N/A'}'")
        return None, "Invalid JSON output from Warp script."
    except FileNotFoundError:
        logger.error(f"Python executable '{python_executable}' or script '{WARP_PY_PATH}' not found.")
        return None, f"Executable or script not found: {python_executable} or {WARP_PY_PATH}"
    except Exception as e:
        logger.error(f"An unexpected error occurred while generating Warp config via external script: {e}", exc_info=True)
        return None, f"Unexpected error: {str(e)}"

```

**`xenon_project/xenon/system_info/routes.py`**
