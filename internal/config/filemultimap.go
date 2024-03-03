package config

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
)

func load(filename string, data map[string]map[string]interface{}) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	currentKey := ""
	currentValues := make(map[string]interface{})
	lineNum := 0
	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		lineNum += 1
		line := fileScanner.Text()
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		} else if trimmed[0] == '#' { // comment
			continue
		} else if line[0] != ' ' { // key
			if currentKey != "" {
				data[currentKey] = currentValues
				currentValues = make(map[string]interface{})
			}
			currentKey = trimmed
		} else { // value
			if currentKey == "" {
				return fmt.Errorf("value before any key line %d", lineNum)
			}
			currentValues[trimmed] = nil
		}
	}
	if currentKey != "" {
		data[currentKey] = currentValues
	}

	return nil
}

type FileMultiMap struct {
	data map[string]map[string]interface{}
}

func NewFileMultiMap(filename string, ctxCancel context.CancelFunc) (*FileMultiMap, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	data := make(map[string]map[string]interface{})
	log.Printf("loading %s", filename)
	if err := load(filename, data); err != nil {
		log.Printf("error loading file: %s", err)
		ctxCancel()
	}
	log.Printf("map: %#v", data) // TODO
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					log.Printf("reloading %s", filename)
					if err := load(filename, data); err != nil {
						log.Printf("error loading file: %s", err)
						ctxCancel()
					}
					log.Printf("map: %#v", data) // TODO
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("error watching %s: %s", filename, err)
				ctxCancel()
			}
		}
	}()
	res := &FileMultiMap{
		data: data,
	}
	return res, nil
}

func (self *FileMultiMap) Get(key string) (map[string]interface{}, bool) {
	res, ok := self.data[key]
	return res, ok
}
