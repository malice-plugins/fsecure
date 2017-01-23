# To update the AV run the following:

```bash
$ docker run --name=fsecure malice/fsecure update
```

## Then to use the updated fsecure container:

```bash
$ docker commit fsecure malice/fsecure:updated
$ docker rm fsecure # clean up updated container
$ docker run --rm malice/fsecure:updated EICAR
```
