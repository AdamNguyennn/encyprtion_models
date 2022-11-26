rmdir /s /q "%~dp0\Debug"
rmdir /s /q "%~dp0\Release"

rmdir /s /q "%~dp0\ECDSA\Debug"
rmdir /s /q "%~dp0\ECDSA\Release"

attrib -r -a -s -h "%~dp0\*.ncb"
attrib -r -a -s -h "%~dp0\*.suo"

attrib -r -a -s -h "%~dp0\ECDSA\*.ncb"
attrib -r -a -s -h "%~dp0\ECDSA\*.suo"

erase /f /s "%~dp0\*.ncb"
erase /f /s "%~dp0\*.plg"
erase /f /s "%~dp0\*.opt"
erase /f /s "%~dp0\*.suo"
erase /f /s "%~dp0\ECDSA\*.user"
erase /f /s "%~dp0\ECDSA\*.aps"