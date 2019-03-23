package main

import "fmt"

var debuggingEnabled bool

//Debugln prints the given string as a line to the terminal if debugging is enabled
func Debugln(s string) {

	if debuggingEnabled {
		fmt.Println(s)
	}
}

//Debugf prints the given fmtString and arguments to the terminal if debugging is enabled
func Debugf(format string, args ...interface{}) {
	if debuggingEnabled {
		fmt.Printf(format+"\n", args...)
	}
}
