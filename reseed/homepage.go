package reseed

import (
	"embed"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/eyedeekay/unembed"
	"gitlab.com/golang-commonmark/markdown"
	"golang.org/x/text/language"
)

// f contains the embedded static content files for the reseed server web interface.
// This includes HTML templates, CSS stylesheets, JavaScript files, and localized content
// for serving the homepage and user interface to reseed service clients.
//
//go:embed content
var f embed.FS

// SupportedLanguages defines all languages available for the reseed server homepage.
// These language tags are used for content localization and browser language matching
// to provide multilingual support for users accessing the reseed service web interface.
var SupportedLanguages = []language.Tag{
	language.English,
	language.Russian,
	language.SimplifiedChinese,
	language.Arabic,
	language.Portuguese,
	language.German,
	language.French,
	language.Spanish,
	language.Indonesian,
	language.Hindi,
	language.Japanese,
	language.Korean,
	language.Bengali,
}

var (
	// CachedLanguagePages stores pre-processed language-specific content pages for performance.
	// Keys are language directory paths and values are rendered HTML content to avoid
	// repeated markdown processing on each request for better response times.
	CachedLanguagePages = map[string]string{}
	// CachedDataPages stores static file content in memory for faster serving.
	// Keys are file paths and values are raw file content bytes to reduce filesystem I/O
	// and improve performance for frequently accessed static resources.
	CachedDataPages = map[string][]byte{}
)

// StableContentPath returns the path to static content files for the reseed server homepage.
// It automatically extracts embedded content to the filesystem if not already present and
// ensures the content directory structure is available for serving web requests.
func StableContentPath() (string, error) {
	// Attempt to get the base content path from the system
	BaseContentPath, ContentPathError := ContentPath()
	// Extract embedded content if directory doesn't exist
	if _, err := os.Stat(BaseContentPath); os.IsNotExist(err) {
		if err := unembed.Unembed(f, BaseContentPath); err != nil {
			return "", err
		} else {
			return BaseContentPath, nil
		}
	}
	return BaseContentPath, ContentPathError
}

// matcher provides language matching functionality for reseed server internationalization.
// It uses the SupportedLanguages list to match client browser language preferences
// with available localized content for optimal user experience.
var matcher = language.NewMatcher(SupportedLanguages)

// header contains the standard HTML document header for reseed server web pages.
// This template includes essential meta tags, CSS stylesheet links, and JavaScript
// imports needed for consistent styling and functionality across all served pages.
var header = []byte(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>This is an I2P Reseed Server</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>`)

// footer contains the closing HTML tags for reseed server web pages.
// This template ensures proper document structure termination for all served content
// and maintains valid HTML5 compliance across the web interface.
var footer = []byte(`  </body>
</html>`)

// md provides configured markdown processor for reseed server content rendering.
// It supports XHTML output and embedded HTML for converting markdown files to
// properly formatted web content with security and standards compliance.
var md = markdown.New(markdown.XHTMLOutput(true), markdown.HTML(true))

// ContentPath determines the filesystem path where reseed server content should be stored.
// It checks the current working directory and creates a content subdirectory for serving
// static files like HTML, CSS, and localized content to reseed service users.
func ContentPath() (string, error) {
	exPath, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// exPath := filepath.Dir(ex)
	if _, err := os.Stat(filepath.Join(exPath, "content")); err != nil {
		return "", err
	}
	return filepath.Join(exPath, "content"), nil
}

func (srv *Server) HandleARealBrowser(w http.ResponseWriter, r *http.Request) {
	_, ContentPathError := StableContentPath()
	if ContentPathError != nil {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	lang, _ := r.Cookie("lang")
	accept := r.Header.Get("Accept-Language")
	lgr.WithField("lang", lang).WithField("accept", accept).Debug("Processing language preferences")
	for name, values := range r.Header {
		// Loop over all values for the name.
		for _, value := range values {
			lgr.WithField("header_name", name).WithField("header_value", value).Debug("Request header")
		}
	}
	tag, _ := language.MatchStrings(matcher, lang.String(), accept)
	lgr.WithField("tag", tag).Debug("Matched language tag")
	base, _ := tag.Base()
	lgr.WithField("base", base).Debug("Base language")

	if strings.HasSuffix(r.URL.Path, "style.css") {
		w.Header().Set("Content-Type", "text/css")
		handleAFile(w, "", "style.css")
	} else if strings.HasSuffix(r.URL.Path, "script.js") {
		w.Header().Set("Content-Type", "text/javascript")
		handleAFile(w, "", "script.js")
	} else {
		image := strings.Replace(r.URL.Path, "/", "", -1)
		if strings.HasPrefix(image, "images") {
			w.Header().Set("Content-Type", "image/png")
			handleAFile(w, "images", strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/"), "images"))
		} else if strings.HasPrefix(image, "ping") {
			PingEverybody()
			http.Redirect(w, r, "/", http.StatusFound)
		} else if strings.HasPrefix(image, "readout") {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(header))
			ReadOut(w)
			w.Write([]byte(footer))
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(header))
			handleALocalizedFile(w, base.String())
			w.Write([]byte(`<ul><li><form method="post" action="/i2pseeds" class="inline">
			<input type="hidden" name="onetime" value="` + srv.Acceptable() + `">
			<button type="submit" name="submit_param" value="submit_value" class="link-button">
			Reseed
			</button>
			</form></li></ul>`))
			ReadOut(w)
			w.Write([]byte(footer))
		}
	}
}

// handleAFile serves static files from the reseed server content directory with caching.
// It loads files from the filesystem on first access and caches them in memory for
// improved performance on subsequent requests, supporting CSS, JavaScript, and image files.
func handleAFile(w http.ResponseWriter, dirPath, file string) {
	BaseContentPath, _ := StableContentPath()
	file = filepath.Join(dirPath, file)
	if _, prs := CachedDataPages[file]; !prs {
		path := filepath.Join(BaseContentPath, file)
		f, err := os.ReadFile(path)
		if err != nil {
			w.Write([]byte("Oops! Something went wrong handling your language. Please file a bug at https://i2pgit.org/go-i2p/reseed-tools\n\t" + err.Error()))
			return
		}
		CachedDataPages[file] = f
		w.Write([]byte(CachedDataPages[file]))
	} else {
		w.Write(CachedDataPages[file])
	}
}

// handleALocalizedFile processes and serves language-specific content with markdown rendering.
// It reads markdown files from language subdirectories, converts them to HTML, and caches
// the results for efficient serving of multilingual reseed server interface content.
func handleALocalizedFile(w http.ResponseWriter, dirPath string) {
	if _, prs := CachedLanguagePages[dirPath]; !prs {
		BaseContentPath, _ := StableContentPath()
		dir := filepath.Join(BaseContentPath, "lang", dirPath)
		files, err := os.ReadDir(dir)
		if err != nil {
			w.Write([]byte("Oops! Something went wrong handling your language. Please file a bug at https://i2pgit.org/go-i2p/reseed-tools\n\t" + err.Error()))
		}
		var f []byte
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".md") {
				return
			}
			trimmedName := strings.TrimSuffix(file.Name(), ".md")
			path := filepath.Join(dir, file.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				w.Write([]byte("Oops! Something went wrong handling your language. Please file a bug at https://i2pgit.org/go-i2p/reseed-tools\n\t" + err.Error()))
				return
			}
			f = append(f, []byte(`<div id="`+trimmedName+`">`)...)
			f = append(f, []byte(md.RenderToString(b))...)
			f = append(f, []byte(`</div>`)...)

		}
		CachedLanguagePages[dirPath] = string(f)
		w.Write([]byte(CachedLanguagePages[dirPath]))
	} else {
		w.Write([]byte(CachedLanguagePages[dirPath]))
	}
}
