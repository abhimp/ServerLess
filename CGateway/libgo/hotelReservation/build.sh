for i in $(ls ./services/)
do
    cd services/${i}
    # go build -o ${i} server.go
    go build -ldflags '-extldflags "-fno-PIC -static"' -buildmode pie -tags 'osusergo netgo static_build' -o ${i} server.go
    # zip ${i}.zip ${i}
    echo "${i} done"
    cd ../..
done