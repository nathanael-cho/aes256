make test

./test

if ! [ -z "$1" ]; then
    make
    cp $1 expected.txt
    ./encrypt $1
    cp $1 encrypted.txt
    ./decrypt $1
    diff $1 expected.txt
fi

make clean
