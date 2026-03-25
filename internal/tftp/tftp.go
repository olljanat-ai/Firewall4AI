// Package tftp implements a simple TFTP server for serving PXE boot files.
// It supports read requests (RRQ) only, in octet (binary) mode.
package tftp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TFTP opcodes.
const (
	opRRQ   uint16 = 1
	opWRQ   uint16 = 2
	opDATA  uint16 = 3
	opACK   uint16 = 4
	opERROR uint16 = 5
)

// TFTP error codes.
const (
	errNotDefined   uint16 = 0
	errFileNotFound uint16 = 1
	errAccessViol   uint16 = 2
	errIllegalOp    uint16 = 4
)

const blockSize = 512

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
	conn, err := net.ListenPacket("udp4", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("tftp listen %s: %w", s.ListenAddr, err)
	}
	defer conn.Close()

	log.Printf("TFTP server listening on %s (root: %s)", s.ListenAddr, s.RootDir)

	buf := make([]byte, 516) // max TFTP packet size
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("TFTP read error: %v", err)
			continue
		}
		if n < 4 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handlePacket(pkt, addr)
	}
}

func (s *Server) handlePacket(pkt []byte, clientAddr net.Addr) {
	opcode := binary.BigEndian.Uint16(pkt[:2])

	switch opcode {
	case opRRQ:
		s.handleRRQ(pkt[2:], clientAddr)
	case opWRQ:
		s.sendError(clientAddr, errAccessViol, "write not supported")
	default:
		s.sendError(clientAddr, errIllegalOp, "unsupported operation")
	}
}

func (s *Server) handleRRQ(data []byte, clientAddr net.Addr) {
	// Parse filename and mode from RRQ.
	filename, mode := parseRRQ(data)
	if filename == "" {
		s.sendError(clientAddr, errNotDefined, "invalid request")
		return
	}

	// Only support octet (binary) mode.
	if strings.ToLower(mode) != "octet" && strings.ToLower(mode) != "netascii" {
		s.sendError(clientAddr, errNotDefined, "unsupported mode: "+mode)
		return
	}

	// Sanitize filename to prevent path traversal.
	clean := filepath.Clean(filename)
	if strings.Contains(clean, "..") {
		s.sendError(clientAddr, errAccessViol, "access denied")
		return
	}

	fullPath := filepath.Join(s.RootDir, clean)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		log.Printf("TFTP RRQ %s from %s: %v", filename, clientAddr, err)
		s.sendError(clientAddr, errFileNotFound, "file not found")
		return
	}

	log.Printf("TFTP RRQ %s from %s (%d bytes)", filename, clientAddr, len(content))

	// Create a new UDP connection for the transfer (TFTP uses a new port per transfer).
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		log.Printf("TFTP: failed to create transfer socket: %v", err)
		return
	}
	defer conn.Close()

	s.sendFile(conn, content, clientAddr)
}

func (s *Server) sendFile(conn net.PacketConn, data []byte, addr net.Addr) {
	blockNum := uint16(1)
	offset := 0

	for {
		end := offset + blockSize
		if end > len(data) {
			end = len(data)
		}
		block := data[offset:end]

		// Build DATA packet.
		pkt := make([]byte, 4+len(block))
		binary.BigEndian.PutUint16(pkt[:2], opDATA)
		binary.BigEndian.PutUint16(pkt[2:4], blockNum)
		copy(pkt[4:], block)

		// Send and wait for ACK with retries.
		sent := false
		for attempt := 0; attempt < 5; attempt++ {
			if _, err := conn.WriteTo(pkt, addr); err != nil {
				log.Printf("TFTP send error: %v", err)
				return
			}

			// Wait for ACK.
			ackBuf := make([]byte, 4)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := conn.ReadFrom(ackBuf)
			if err != nil {
				continue // timeout, retry
			}
			if n >= 4 && binary.BigEndian.Uint16(ackBuf[:2]) == opACK {
				ackBlock := binary.BigEndian.Uint16(ackBuf[2:4])
				if ackBlock == blockNum {
					sent = true
					break
				}
			}
		}
		if !sent {
			log.Printf("TFTP: transfer to %s timed out at block %d", addr, blockNum)
			return
		}

		// If this was the last block (less than blockSize), we're done.
		if len(block) < blockSize {
			return
		}

		offset += blockSize
		blockNum++
	}
}

func (s *Server) sendError(addr net.Addr, code uint16, msg string) {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return
	}
	defer conn.Close()

	pkt := make([]byte, 4+len(msg)+1)
	binary.BigEndian.PutUint16(pkt[:2], opERROR)
	binary.BigEndian.PutUint16(pkt[2:4], code)
	copy(pkt[4:], msg)
	pkt[4+len(msg)] = 0 // null terminator

	conn.WriteTo(pkt, addr)
}

// parseRRQ extracts filename and mode from an RRQ payload (after opcode).
func parseRRQ(data []byte) (string, string) {
	parts := splitNullStrings(data, 2)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func splitNullStrings(data []byte, max int) []string {
	var result []string
	start := 0
	for i := 0; i < len(data) && len(result) < max; i++ {
		if data[i] == 0 {
			result = append(result, string(data[start:i]))
			start = i + 1
		}
	}
	return result
}
