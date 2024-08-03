module github.com/elazarl/goproxy


go 1.22.2

require (
	github.com/conduitio/bwlimit v0.1.0
	github.com/elazarl/goproxy/ext v0.0.0-20231117061959-7cc037d33fb5
)

//replace github.com/conduitio/bwlimit => github.com/limbo127/bwlimit v0.0.1 // indirect

require (
	github.com/gorhill/cronexpr v0.0.0-20180427100037-88b0669f7d75
	golang.org/x/time v0.5.0 // indirect
)

