package reseed

import (
	"archive/zip"
	"bytes"
	"io"
)

func zipSeeds(seeds []routerInfo) ([]byte, error) {
	// Create a buffer to write our archive to.
	buf := new(bytes.Buffer)

	// Create a new zip archive.
	zipWriter := zip.NewWriter(buf)

	// Add some files to the archive.
	for _, file := range seeds {
		fileHeader := &zip.FileHeader{Name: file.Name, Method: zip.Deflate}
		fileHeader.SetModTime(file.ModTime)
		zipFile, err := zipWriter.CreateHeader(fileHeader)
		if err != nil {
			lgr.WithError(err).WithField("file_name", file.Name).Error("Failed to create zip file header")
			return nil, err
		}

		_, err = zipFile.Write(file.Data)
		if err != nil {
			lgr.WithError(err).WithField("file_name", file.Name).Error("Failed to write file data to zip")
			return nil, err
		}
	}

	if err := zipWriter.Close(); err != nil {
		lgr.WithError(err).Error("Failed to close zip writer")
		return nil, err
	}

	return buf.Bytes(), nil
}

func uzipSeeds(c []byte) ([]routerInfo, error) {
	input := bytes.NewReader(c)
	zipReader, err := zip.NewReader(input, int64(len(c)))
	if nil != err {
		lgr.WithError(err).WithField("zip_size", len(c)).Error("Failed to create zip reader")
		return nil, err
	}

	var seeds []routerInfo
	for _, f := range zipReader.File {
		rc, err := f.Open()
		if err != nil {
			lgr.WithError(err).WithField("file_name", f.Name).Error("Failed to open file from zip")
			return nil, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if nil != err {
			lgr.WithError(err).WithField("file_name", f.Name).Error("Failed to read file data from zip")
			return nil, err
		}

		seeds = append(seeds, routerInfo{Name: f.Name, Data: data})
	}

	return seeds, nil
}
