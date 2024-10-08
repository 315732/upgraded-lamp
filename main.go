package main

import (
    "bufio"
    "fmt"
    "log"
    "net/http"
    "os"
    "sync"
    "time"
	"flag"
)

const maxConcurrentRequests = 10 // Limit for concurrent requests

func scan(url string, wordlist string) {
    // Open the file containing the payloads
    file, err := os.Open(wordlist)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // Ensure the file is closed after reading

    // Create a scanner to read the file line by line
    scanner := bufio.NewScanner(file)

    var payloads []string // Declare a slice to hold payloads

    // Read each line (payload) into the slice
    for scanner.Scan() {
        payloads = append(payloads, scanner.Text())
    }

    // Check for errors during reading
    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

    var wg sync.WaitGroup         // WaitGroup to wait for all goroutines to finish
    results := make(chan string)  // Channel to receive results
    sem := make(chan struct{}, maxConcurrentRequests) // Semaphore for limiting concurrent requests

    // Start a goroutine to print results
    go func() {
        for result := range results {
            fmt.Print(result)
        }
    }()

    // Create an HTTP client with a timeout
    client := &http.Client{
        Timeout: 5 * time.Second, // Set a timeout of 5 seconds for each request
    }

    // Iterate over each payload and perform the HTTP request in a goroutine
    for _, payload := range payloads {
        wg.Add(1) // Increment the WaitGroup counter

        // Acquire a semaphore slot
        sem <- struct{}{}
        go func(payload string) {
            defer wg.Done() // Ensure wg.Done() is called when this goroutine completes
            defer func() { <-sem }() // Release the semaphore slot

            resp, err := client.Get(url + payload)
            if err != nil {
                fmt.Printf("Error checking URL with payload %s: %s\n", payload, err)
                return // Exit if there's an error
            }
            defer resp.Body.Close() // Close the response body when done

            // Check the response status code
            if resp.StatusCode == http.StatusOK {
                results <- fmt.Sprintf("\033[32m[*] SQL Injection Vulnerability Found In %s%s\033[0m\n", url, payload)
            }
        }(payload)
    }

    wg.Wait()         // Wait for all goroutines to finish
    close(results)    // Close the results channel when done
}

func main() {
    urlPtr := flag.String("u", "", "URL to scan")
    wordlistPtr := flag.String("w", "", "Path to the wordlist file")

    flag.Parse()

    if *urlPtr == "" || *wordlistPtr == "" {
        fmt.Printf("Both -u (URL) and -w (wordlist) flags are required.")
        return nil
    }

    fmt.Printf("\nURL provided: %s\n", *urlPtr)
    fmt.Printf("Wordlist provided: %s\n\n", *wordlistPtr)

    scan(*urlPtr, *wordlistPtr)
}
