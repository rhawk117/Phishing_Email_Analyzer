import traceback
from datetime import datetime
import os

class Log:
    dir = "app_logs"
    format = "*" * 80

    @staticmethod
    def record_exc(exception: Exception) -> None:
        time = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        log_name = f"app_log{time}.log"
        file = os.path.join(Log.dir, log_name)
        Log._make_dir()

        with open(file, "a") as f:
            f.write(f"{Log.format}\n")
            f.write(f"[ EXCEPTION OCCURED ]{exception}\n\n")
            f.write(f"{exception}\n")
            f.write(f"{traceback.format_exc()}\n")
            f.write(f"{Log.format}\n")

    @staticmethod
    def _make_dir() -> None:
        if not os.path.exists(Log.dir):
            os.makedirs(Log.dir)