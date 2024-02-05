// main.go
package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"
)

type Item struct {
	Date        string `json:"date"`
	Action      string `json:"action"`
	Remediation string `json:"remediation"`
	SourceIP    string `json:"sourceip"`
	Mitre       string `json:"mitre"`
	Hostname    string `json:"hostname"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	QueryString string `json:"querystring"`
	FVuln       string `json:"fvuln"`
	UserAgent   string `json:"useragent"`
	Vuln        string `json:"vuln"`
}

var itemList []Item

func main() {
	// Load data from CSV file
	if err := loadDataFromCSV("logs.csv"); err != nil {
		fmt.Println("Error loading data:", err)
		return
	}

	// Set up API endpoint
	http.HandleFunc("/logs", itemsHandler)
	http.HandleFunc("/help", helpHandler)

	// Set the default handler to redirect the root path to /help
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/help", http.StatusSeeOther)
	})

	// Start the server
	fmt.Println("Server is listening on :8080...")
	http.ListenAndServe(":8080", nil)
}

func itemsHandler(w http.ResponseWriter, r *http.Request) {

	var filteredItems []Item

	// Get the value of the "category" query parameter
	category1 := r.URL.Query().Get("Mitre")
	category := r.URL.Query().Get("FoundVuln")

	// Filter items based on the category
	filteredItems = filterItemsByCategory(category, category1)

	// Format items as a table
	table := formatItemsTable(filteredItems, category, category1)

	// Convert the list to JSON and send it in the response
	//w.Header().Set("Content-Type", "application/json")
	//json.NewEncoder(w).Encode(filteredItems)

	// Set the content type to plain text and send it in the response
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, table)
}

func formatItemsTable(items []Item, category string, category1 string) string {
	// Use a bytes.Buffer as an intermediate destination for tabwriter
	var buffer bytes.Buffer
	w := tabwriter.NewWriter(&buffer, 0, 0, 3, ' ', 0)

	if category == "Yes" && category1 == "Show" {
		// Show only needed info
		// Add headers
		fmt.Fprintln(w, "Date\tAction\tSourceIP\tQueryString\tUserAgent\tFoundVuln?\tVulnerability\tRemediation\tMitre")

		// Add data rows
		for _, item := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", item.Date, item.Action, truncate(item.SourceIP, 8), truncate(item.QueryString, 30), truncate(item.UserAgent, 10), item.FVuln, truncate(item.Vuln, 18), item.Remediation, item.Mitre)
		}

	} else {

		// Add headers
		fmt.Fprintln(w, "Date\tAction\tSourceIP\tHostname\tMethod\tPath\tQueryString\tUserAgent")

		// Add data rows
		for _, item := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", item.Date, item.Action, item.SourceIP, truncate(item.Hostname, 20), item.Method, truncate(item.Path, 30), item.QueryString, truncate(item.UserAgent, 33))
		}
	}

	// Flush the tabwriter
	w.Flush()

	// Convert the buffer content to a string
	return buffer.String()
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

func filterItemsByCategory(category string, category1 string) []Item {
	var filteredItems []Item
	seenIDs := make(map[string]bool)
	//fmt.Println("Server is listening on :8080...", category)

	if category == "Yes" && category1 == "Show" {

		for _, item := range itemList {
			//fmt.Printf("Checking item: %+v\n", item)
			// If category is empty or matches the item's category, include it in the result
			if (category == "" || category == item.FVuln) && !seenIDs[item.Action] {
				//fmt.Printf("Adding item to filtered list\n")
				filteredItems = append(filteredItems, item)
				seenIDs[item.Action] = true
				//fmt.Println("Adentro del for", category)
			}
		}
	} else {
		for _, item := range itemList {
			// If category is empty or matches the item's category, include it in the result
			if category == "" || category == item.FVuln {
				filteredItems = append(filteredItems, item)
				//fmt.Printf("Adding item to filtered list\n")
			}
		}
	}

	return filteredItems
}

func loadDataFromCSV(filename string) error {
	// Open the CSV file
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a CSV reader
	reader := csv.NewReader(file)

	// Read all records from the CSV file
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	// Parse CSV records into Item structs
	for _, record := range records {
		if len(record) >= 2 {
			itemList = append(itemList, Item{record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7], record[8], record[9], record[10], record[11]})
		}
	}

	return nil
}

func helpHandler(w http.ResponseWriter, r *http.Request) {
	// Define help information in plain text
	helpText := `
Available Endpoints:
- /logs: Get a list of the traffic logs with optional 'FoundVuln' and 'Mitre' parameters
- /help: Get help information about available endpoints

Parameters:
- FoundVuln: Filter vulnerable traffic logs (e.g., /logs?FoundVuln=Yes/No)
- Mitre: Filter the Mitre info about the vulnerabilities, mandatory the parameter FoundVuln=Yes (e.g., /logs?FoundVuln=Yes&Mitre=Show)
	`

	// Set the content type to plain text and send it in the response
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, helpText)
}
