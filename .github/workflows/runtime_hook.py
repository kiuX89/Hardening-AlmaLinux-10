import os

if "LD_LIBRARY_PATH_ORIG" in os.environ:
    os.environ["LD_LIBRARY_PATH"] = os.environ.pop("LD_LIBRARY_PATH_ORIG")
else:
    os.environ.pop("LD_LIBRARY_PATH", None)
