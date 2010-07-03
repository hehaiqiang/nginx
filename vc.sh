
#SDK=/c/program\ files/microsoft\ sdks/windows/v7.0a
SDK=/j/tools/microsoftsdks/windows/v7.1

export PATH=$SDK/bin:$PATH


#VS=/c/program\ files/microsoft\ visual\ studio\ 8
#VS=/j/tools/vc2008
VS=/j/tools/vs10

IDE=$VS/common7/ide
VC=$VS/vc

export CC=cl
export INCLUDE=$SDK/include:$VC/include:$INCLUDE
export LIB=$SDK/lib:$VC/lib:$LIB
export PATH=$IDE:$VC/bin:$PATH
