package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-github/v62/github"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	router := gin.Default()

	v1 := router.Group("/api/v1")
	v1.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	v1.POST("/token", func(c *gin.Context) {
		println(c.GetHeader("Authorization"))
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		jwkSet, err := fetchJWKSet("https://token.actions.githubusercontent.com/.well-known/jwks")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		valid, _, err := VerifyTokenWithJWKSet(tokenString, jwkSet)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}
		tr := http.DefaultTransport
		homeDir, err := os.UserHomeDir()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		itr, err := ghinstallation.NewKeyFromFile(tr, 937582, 52501793, filepath.Join(homeDir, "Downloads", "octogate.2024-07-04.private-key.pem"))
		if err != nil {
			log.Fatal(err)
		}
		_, err = itr.Token(context.Background())
		client := github.NewClient(&http.Client{Transport: itr})
		atr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, 937582, filepath.Join(homeDir, "Downloads", "octogate.2024-07-04.private-key.pem"))
		if err != nil {
			panic(err)
		}
		client = github.NewClient(&http.Client{Transport: atr})
		tokenOptions := &github.InstallationTokenListRepoOptions{
			Repositories: []string{"effective-octo-engine"},
			Permissions: &github.InstallationPermissions{
				Contents: github.String("write"),
				Issues:   github.String("write"),
			},
		}
		installationToken, _, err := client.Apps.CreateInstallationTokenListRepos(c, 52501793, tokenOptions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, nil)
			log.Println(err)
			return
		}
		c.JSON(http.StatusOK, installationToken)
	})
	router.Run()
}

func fetchJWKSet(url string) (*jose.JSONWebKeySet, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWK Set: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWK Set: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWK Set response: %w", err)
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK Set: %w", err)
	}
	return &jwks, nil
}

type CustomClaims struct {
	Sub string `json:"sub"`
}

func VerifyTokenWithJWKSet(tokenString string, jwks *jose.JSONWebKeySet) (bool, CustomClaims, error) {
	var signatureAlgorithms []jose.SignatureAlgorithm
	for _, key := range jwks.Keys {
		signatureAlgorithms = append(signatureAlgorithms, jose.SignatureAlgorithm(key.Algorithm))
	}
	var claims CustomClaims
	tok, err := jose.ParseSigned(tokenString, signatureAlgorithms)
	if err != nil {
		return false, claims, fmt.Errorf("failed to parse token: %w", err)
	}
	for _, sig := range tok.Signatures {
		if key := jwks.Key(sig.Header.KeyID); len(key) > 0 {
			output, err := tok.Verify(key[0].Key)
			if err != nil {
				continue // Try the next key
			}
			// If verification is successful, unmarshal the claims
			err = json.Unmarshal(output, &claims)
			if err != nil {
				return false, claims, fmt.Errorf("failed to unmarshal claims: %w", err)
			}
			return true, claims, nil // Token is valid and claims are parsed
		}
	}

	return false, claims, fmt.Errorf("failed to verify token: no matching keys")
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}
