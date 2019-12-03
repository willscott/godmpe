module github.com/willscott/godmpe

go 1.13

replace (
	github.com/glaslos/ssdeep => github.com/LordNoteworthy/ssdeep v1.0.0
	github.com/go-delve/delve => ./delve
)

require (
	github.com/edsrzf/mmap-go v1.0.0
	github.com/go-delve/delve v1.3.2
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/willscott/pefile-go v0.0.0-20191203022938-b1d80162b106
	golang.org/x/arch v0.0.0-20191101135251-a0d8588395bd // indirect
	golang.org/x/crypto v0.0.0-20191117063200-497ca9f6d64f // indirect
)
