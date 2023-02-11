del "./build" /s /q
mkdir "./build"
echo "../build.bat" > "./build/build.bat"
cd "./build"
cmake ..
cd "../"
