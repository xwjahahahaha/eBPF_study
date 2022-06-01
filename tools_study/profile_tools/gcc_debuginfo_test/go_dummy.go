package main

import (
	"fmt"
	"time"
)

type T struct {
}

func (t *T) some_function(a, b int) int {
	c := a + b
	return c
}

func main() {
	t := T{}
	fmt.Printf("%p\n", t.some_function)
	fmt.Printf("result = %d\n", t.some_function(42, 11))
	time.Sleep(1000 * time.Second)
}
