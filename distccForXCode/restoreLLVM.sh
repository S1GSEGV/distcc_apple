cd `dirname $0`

XcodePath=`xcode-select --print-path`


cd "$XcodePath/../PlugIns/Xcode3Core.ideplugin/Contents/SharedSupport/Developer/Library/Xcode/Plug-ins/Clang LLVM 1.0.xcplugin/Contents/Resources"

sudo sed -i "" "s/ExecPath = \"distcc\";/ExecPath = \"clang\";/g" "./Clang LLVM 1.0.xcspec"

