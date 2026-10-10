@echo off
setlocal
cd /d "%~dp0.."
echo ============================================
echo  awdshell 单文件构建（Wails 原生窗口）
echo ============================================
echo.
echo  前端是免构建的静态资源（frontend\dist），会随 Go 一起打进单个可执行文件。
echo  前置依赖：Go 1.24+ 与 Wails CLI：
echo      go install github.com/wailsapp/wails/v2/cmd/wails@latest
echo.
wails build -clean -trimpath -ldflags "-s -w"
if errorlevel 1 goto :err

echo.
echo 完成: build\bin\awdshell.exe
for %%F in (build\bin\awdshell.exe) do echo   大小: %%~zF 字节
echo.
echo 直接双击运行，或命令行指定参数：
echo    build\bin\awdshell.exe
goto :eof

:err
echo.
echo 构建失败，请检查上面的输出。
exit /b 1
