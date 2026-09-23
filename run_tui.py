"""DICOM 脱敏工具启动入口"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    if "--api" in sys.argv:
        # API 模式
        import uvicorn
        from dicom_deid.api import app
        print("Starting DICOM-DeID API server on http://0.0.0.0:8080")
        uvicorn.run(app, host="0.0.0.0", port=8080)
    else:
        # TUI 模式
        from dicom_deid.tui import DicomDeidApp
        DicomDeidApp().run()


if __name__ == "__main__":
    main()
