package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/oschwald/geoip2-golang/v2"
)

type timezoneEstimator struct {
	reader *geoip2.Reader
}

func (te *timezoneEstimator) setupGeoipDatabase() {
	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Printf("Couldn't setup GeoLite database: %v", err)
		return
	}

	te.reader = db
}

// Close releases the GeoIP database resources.
func (te *timezoneEstimator) Close() error {
	if te.reader == nil {
		return nil
	}

	err := te.reader.Close()
	te.reader = nil
	return err
}

func (te *timezoneEstimator) estimateTimezone(s ssh.Session) *time.Location {
	if te.reader == nil {
		return time.UTC
	}

	remoteAddr := s.Context().RemoteAddr()
	if remoteAddr == nil {
		log.Printf("Couldn't determine remote address")
		return time.UTC
	}

	stringIP, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		log.Printf("Couldn't parse remote address %q: %v", remoteAddr.String(), err)
		return time.UTC
	}

	ip, err := netip.ParseAddr(stringIP)
	if err != nil {
		log.Printf("Couldn't parse remote IP %q: %v", stringIP, err)
		return time.UTC
	}

	record, err := te.reader.City(ip)
	if err != nil {
		log.Printf("Couldn't look up GeoIP data for %s: %v", ip, err)
		return time.UTC
	}

	if !record.HasData() {
		log.Printf("No GeoIP data found for IP %s", ip)
		return time.UTC
	}

	timezone, err := time.LoadLocation(record.Location.TimeZone)
	if err != nil {
		log.Printf("Couldn't use timezone %q: %v", record.Location.TimeZone, err)
		return time.UTC
	}

	fmt.Printf("City: %s\n", record.City.Names.English)

	return timezone
}
