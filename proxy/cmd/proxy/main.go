package main

import (
	"fmt"
	"log"
	"immunisoc-nexus/proxy/internal/classification"
)

func main() {
    // Call the function to "use" the package
    fmt.Println(classification.AnalyzeTraffic())

    log.Println("Neutrophil Proxy Membrane Initialized.")
    // ... rest of your code
}