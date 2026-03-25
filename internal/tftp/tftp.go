// Package tftp implements a TFTP server for serving PXE boot files.
// It supports read requests (RRQ) only, in octet (binary) mode.
// Uses github.com/pin/tftp/v3 for protocol handling.
package tftp

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	gotftp "github.com/pin/tftp/v3"
)

// Server is a TFTP server that serves files from a root directory.
type Server struct {
	ListenAddr string // e.g., ":69"
	RootDir    string // directory containing boot files
}

// NewServer creates a new TFTP server.
func NewServer(listenAddr, rootDir string) *Server {
	return &Server{
		ListenAddr: listenAddr,
		RootDir:    rootDir,
	}
}

// ListenAndServe starts the TFTP server.
func (s *Server) ListenAndServe() error {
	srv := gotftp.NewServer(s.readHandler, nil)
	srv.SetTimeout(3 * time.Second)

	log.Printf("TFTP server listening on %s (root: %s)", s.ListenAddr, s.RootDir)
	return srv.ListenAndServe(s.ListenAddr)
}

// readHandler handles TFTP read requests by serving files from RootDir.
func (s *Server) readHandler(filename string, rf io.ReaderFrom) error {
	// Sanitize filename to prevent path traversal.
	clean := filepath.Clean(filename)
	if strings.Contains(clean, "..") {
		log.Printf("TFTP RRQ %s: access denied (path traversal)", filename)
		return fmt.Errorf("access denied")
	}

	fullPath := filepath.Join(s.RootDir, clean)
	file, err := os.Open(fullPath)
	if err != nil {
		log.Printf("TFTP RRQ %s: %v", filename, err)
		return fmt.Errorf("file not found")
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("file not found")
	}

	log.Printf("TFTP RRQ %s (%d bytes)", filename, stat.Size())

	n, err := rf.ReadFrom(file)
	if err != nil {
		log.Printf("TFTP transfer error for %s: %v", filename, err)
		return err
	}
	log.Printf("TFTP sent %s (%d bytes)", filename, n)
	return nil
}
