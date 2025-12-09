@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=amd64
msbuild "D:\git\cl-evict\gpu-memory-tracker.sln" /p:Configuration=Release /p:Platform=x64
