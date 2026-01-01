package main

import (
	"github.com/oschwald/geoip2-golang/v2"
	"github.com/charmbracelet/ssh"
	"log"
	"net/netip"
	"net"
	"fmt"
	"time"
)

type timezoneEstimator struct {
	reader *geoip2.Reader
	available bool

}


func (te *timezoneEstimator) setupGeoipDatabase(){
	db, err := geoip2.Open("GeoLite2-City.mmdb")

	if(err!=nil){
		te.available = false
		fmt.Println("Couldn't setup geolite database")
		return 
	}

	te.available = true
	te.reader = db
}

func (te *timezoneEstimator) estimateTimezone(s ssh.Session) *time.Location {

	if(!te.available){
		return time.UTC
	}

	stringip, _, err := net.SplitHostPort(s.Context().RemoteAddr().String())

	if (err!=nil){
		log.Fatal(err)
	}

	ip, err := netip.ParseAddr(stringip)

	if(err!=nil){
		log.Fatal(err)
	}

	record, err := te.reader.City(ip)
	if err != nil {
		log.Fatal(err)
	}

	if !record.HasData() {
		fmt.Printf("No data found for this IP")
		return time.UTC
	}

	timezone, err := time.LoadLocation(record.Location.TimeZone)

	if(err!=nil){
		fmt.Printf("Couldn't use timeone %s", record.Location.TimeZone)
		return time.UTC
	}

	fmt.Printf("City: %s", record.City.Names.English)

	return timezone
}