// SubOver is a tool for discovering subdomain takeovers
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/parnurzeal/gorequest"
)

// Structure for each provider stored in providers.json file
type ProviderData struct {
	Name     string   `json:"name"`
	Cname    []string `json:"cname"`
	Response []string `json:"response"`
}

var Providers []ProviderData

var Targets []string

var (
	HostsList  string
	Threads    int
	All        bool
	Verbose    bool
	ForceHTTPS bool
	Timeout    int
	OutputFile string
)

func InitializeProviders() {
	raw := []byte(`[
    {
        "name":"github", 
        "cname":["github.io", "github.map.fastly.net"], 
        "response":["There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"]
    },
    {
        "name":"heroku", 
        "cname":["herokudns.com", "herokussl.com", "herokuapp.com"], 
        "response":["There's nothing here, yet.", "herokucdn.com/error-pages/no-such-app.html", "<title>No such app</title>"]
    },
    {
        "name":"tumblr",
        "cname":["tumblr.com","domains.tumblr.com"],
        "response":["There's nothing here.", "Whatever you were looking for doesn't currently exist at this address."]
    },
    {
        "name":"shopify",
        "cname":["myshopify.com"],
        "response":["Sorry, this shop is currently unavailable.", "Only one step left!"]
    },
    {
        "name":"instapage",
        "cname":["pageserve.co", "secure.pageserve.co", "https://instapage.com/"],
        "response":["You've Discovered A Missing Link. Our Apologies!"]
    },
    {
        "name":"tictail",
        "cname":["tictail.com", "domains.tictail.com"],
        "response":["Building a brand of your own?", "to target URL: <a href=\"https://tictail.com", "Start selling on Tictail."]
    },
    {
        "name":"campaignmonitor",
        "cname":["createsend.com", "name.createsend.com"],
        "response":["<strong>Trying to access your account?</strong>", "Double check the URL or <a href=\"mailto:help@createsend.com"]
    },
    {
        "name":"cargocollective",
        "cname":["cargocollective.com"],
        "response":["<div class=\"notfound\">", "404 Not Found<br>"]
    },
    {
        "name":"statuspage",
        "cname":["statuspage.io"],
        "response":["Better Status Communication", "You are being <a href=\"https://www.statuspage.io\">redirected"]
    },
    {
        "name":"amazonaws",
        "cname":["amazonaws.com"],
        "response":["NoSuchBucket", "The specified bucket does not exist"]
    },
    {
        "name":"bitbucket",
        "cname":["bitbucket.org","bitbucket.io"],	
        "response":["The page you have requested does not exist", "Repository not found"]
    },
    {
        "name":"smartling",
        "cname":["smartling.com"],
        "response":["Domain is not configured"]
    },
    {
        "name":"acquia",
        "cname":["acquia.com", "acquia-test.co"],
        "response":["If you are an Acquia Cloud customer and expect to see your site at this address", "The site you are looking for could not be found."]
    },
    {
        "name":"fastly",
        "cname":["fastly.net"],
        "response":["Please check that this domain has been added to a service", "Fastly error: unknown domain"]
    },
    {
        "name":"pantheon",
        "cname":["pantheonsite.io"],
        "response":["The gods are wise", "The gods are wise, but do not know of the site which you seek."]
    },
    {
        "name":"uservoice",
        "cname":["uservoice.com"],
        "response":["This UserVoice subdomain is currently available!"]
    },
    {
        "name":"ghost",
        "cname":["ghost.io"],
        "response":["The thing you were looking for is no longer here", "The thing you were looking for is no longer here, or never was"]
    },
    {
        "name":"tilda",
        "cname":["tilda.ws"],
        "response":["Domain has been assigned"]
    },
    {
        "name":"wordpress",
        "cname":["wordpress.com"],	
        "response":["Do you want to register"]
    },
    {
        "name":"teamwork",
        "cname":["teamwork.com"],
        "response":["Oops - We didn't find your site."]
    },
    {
        "name":"helpjuice",
        "cname":["helpjuice.com"],
        "response":["We could not find what you're looking for."]
    },
    {
        "name":"helpscout",
        "cname":["helpscoutdocs.com"],
        "response":["No settings were found for this company:"]
    },
    {
        "name":"cargo",
        "cname":["cargocollective.com"],
        "response":["If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel."]
    },
    {
        "name":"feedpress",
        "cname":["redirect.feedpress.me"],
        "response":["The feed has not been found."]
    },
    {
        "name":"surge",
        "cname":["surge.sh"],
        "response":["project not found"]
    },
    {
        "name":"surveygizmo",
        "cname":["privatedomain.sgizmo.com", "privatedomain.surveygizmo.eu", "privatedomain.sgizmoca.com"],
        "response":["data-html-name"]
    },
    {
        "name":"mashery",
        "cname":["mashery.com"],
        "response":["Unrecognized domain <strong>"]
    },
    {
        "name":"intercom",
        "cname":["custom.intercom.help"],
        "response":["This page is reserved for artistic dogs.","<h1 class=\"headline\">Uh oh. That page doesn’t exist.</h1>"]
    },
    {
        "name":"webflow",
        "cname":["proxy.webflow.io", "proxy-ssl.webflow.com", "proxy.webflow.com"],
        "response":["<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>"]
    },
    {
        "name":"kajabi",
        "cname":["endpoint.mykajabi.com"],
        "response":["<h1>The page you were looking for doesn't exist.</h1>"]
    },
    {
        "name":"thinkific",
        "cname":["thinkific.com"],
        "response":["You may have mistyped the address or the page may have moved."]
    },
    {
        "name":"tave",
        "cname":["clientaccess.tave.com"],
        "response":["<h1>Error 404: Page Not Found</h1>"]
    },
    {
        "name":"wishpond",
        "cname":["wishpond.com"],
        "response":["https://www.wishpond.com/404?campaign=true"]
    },
    {
        "name":"aftership",
        "cname":["aftership.com"],
        "response":["Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist."]
    },
    {
        "name":"aha",
        "cname":["ideas.aha.io"],
        "response":["There is no portal here ... sending you back to Aha!"]
    },
    {
        "name":"brightcove",
        "cname":["brightcovegallery.com", "gallery.video", "bcvp0rtal.com"],
        "response":["<p class=\"bc-gallery-error-code\">Error Code: 404</p>"]
    },
    {
        "name":"bigcartel",
        "cname":["bigcartel.com"],
        "response":["<h1>Oops! We couldn&#8217;t find that page.</h1>"]
    },
    {
        "name":"activecompaign",
        "cname":["activehosted.com"],
        "response":["alt=\"LIGHTTPD - fly light.\""]
    },
    {
        "name":"compaignmonitor",
        "cname":["createsend.com"],
        "response":["Double check the URL or <a href=\"mailto:help@createsend.com"]
    },
    {
        "name":"acquia",
        "cname":["acquia-test.co"],
        "response":["The site you are looking for could not be found."]
    },
    {
        "name":"proposify",
        "cname":["proposify.biz"],
        "response":["If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz"]
    },
    {
        "name":"simplebooklet",
        "cname":["simplebooklet.com"],
        "response":["We can't find this <a href=\"https://simplebooklet.com"]
    },
    {
        "name":"getresponse",
        "cname":[".gr8.com"],
        "response":["With GetResponse Landing Pages, lead generation has never been easier"]
    },
    {
        "name":"vend",
        "cname":["vendecommerce.com"],
        "response":["Looks like you've traveled too far into cyberspace."]
    },
    {
        "name":"jetbrains",
        "cname":["myjetbrains.com"],
        "response":["is not a registered InCloud YouTrack."]
    },
    {
        "name":"azure",
        "cname":[".azurewebsites.net",".cloudapp.net",".cloudapp.azure.com",".trafficmanager.net",".blob.core.windows.net",".azure-api.net",".azurehdinsight.net",".azureedge.net"],
        "response":["404 Web Site not found"]
    },
    {
        "name": "readme",
        "cname": ["readme.io"],
        "fingerprint": ["Project doesnt exist... yet!"]
    },
    {
        "name": "smugmug",
        "cname": ["domains.smugmug.com"],
        "response": ["{\"text\":\"Page Not Found\""]
    },
    {
        "name": "airee",
        "cname": ["cdn.airee.ru"],
        "response": ["Ошибка 402. Сервис Айри.рф не оплачен"]
    },
    {
        "name": "kinsta",
        "cname": ["kinsta.com"],
        "response": ["No Site For Domain"]
    },
    {
        "name": "launchrock",
        "cname": ["launchrock.com"],
        "response": ["It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us."]
    },
    {
        "name": "Strikingly",
        "cname": ["s.strikinglydns.com"],
        "response": ["But if you're looking to build your own website","you've come to the right place."]
    },
    {
        "name": "Uptimerobot",
        "cname": ["stats.uptimerobot.com"],
        "response": ["page not found"]
    },
    {
        "name": "HatenaBlog",
        "cname": [""],
        "response": ["404 Blog is not found", "Sorry, we can't find the page you're looking for."]
    },
    {
        "name": "wufoo",
        "cname": ["wufoo.com"],
        "response": ["Profile not found", "Hmmm....something is not right."]
    },
    {
        "name": "hubspot",
        "cname": ["hubspot.com"],
        "response": ["Domain not found", "does not exist in our system"]
    },
    {
        "name": "jazzhr",
        "cname": ["applytojob.com"],
        "response": ["This account no longer active"]
    }
]`)

	err := json.Unmarshal(raw, &Providers)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
}

func ReadFile(file string) (lines []string, err error) {
	fileHandle, err := os.Open(file)
	if err != nil {
		return lines, err
	}

	defer fileHandle.Close()
	fileScanner := bufio.NewScanner(fileHandle)

	for fileScanner.Scan() {
		lines = append(lines, fileScanner.Text())
	}

	return lines, nil
}

func Get(url string, timeout int, https bool) (resp gorequest.Response, body string, errs []error) {
	if https == true {
		url = fmt.Sprintf("https://%s/", url)
	} else {
		url = fmt.Sprintf("http://%s/", url)
	}

	resp, body, errs = gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		Timeout(time.Duration(timeout)*time.Second).Get(url).
		Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0").
		End()

	return resp, body, errs
}

func ParseArguments() {
	flag.IntVar(&Threads, "t", 20, "Number of threads to use")
	flag.StringVar(&HostsList, "l", "", "List of hosts to check takeovers on")
	flag.BoolVar(&All, "a", false, "Check all hosts regardless of CNAME")
	flag.BoolVar(&Verbose, "v", false, "Show verbose output")
	flag.BoolVar(&ForceHTTPS, "https", false, "Force HTTPS connections (Default: http://)")
	flag.IntVar(&Timeout, "timeout", 10, "Seconds to wait before timeout")
	flag.StringVar(&OutputFile, "o", "", "File to write enumeration output to")

	flag.Parse()
}

func CNAMEExists(key string) bool {
	for _, provider := range Providers {
		for _, cname := range provider.Cname {
			if strings.Contains(key, cname) {
				return true
			}
		}
	}

	return false
}

func Check(target string, TargetCNAME string) {
	_, body, errs := Get(target, Timeout, ForceHTTPS)
	if len(errs) <= 0 {
		if TargetCNAME == "ALL" {
			for _, provider := range Providers {
				for _, response := range provider.Response {
					if strings.Contains(body, response) == true {
						fmt.Printf("\n[\033[31;1;4m%s\033[0m] Takeover Possible At %s ", provider.Name, target)
						return
					}
				}
			}
		} else {
			// This is a less false positives way
			for _, provider := range Providers {
				for _, cname := range provider.Cname {
					if strings.Contains(TargetCNAME, cname) {
						for _, response := range provider.Response {
							if strings.Contains(body, response) == true {
								if provider.Name == "cloudfront" {
									_, body2, _ := Get(target, 120, true)
									if strings.Contains(body2, response) == true {
										fmt.Printf("\n[\033[31;1;4m%s\033[0m] Takeover Possible At %s", provider.Name, target)
									}
								} else {
									fmt.Printf("\n[\033[31;1;4m%s\033[0m] Takeover Possible At %s with CNAME %s", provider.Name, target, TargetCNAME)
								}
							}
							return
						}
					}
				}
			}
		}
	} else {
		if Verbose == true {
			log.Printf("[ERROR] Get: %s => %v", target, errs)
		}
	}

	return
}

func Checker(target string) {
	TargetCNAME, err := net.LookupCNAME(target)
	if err != nil {
		return
	} else {
		if All != true && CNAMEExists(TargetCNAME) == true {
			if Verbose == true {
				log.Printf("[SELECTED] %s => %s", target, TargetCNAME)
			}
			Check(target, TargetCNAME)
		} else if All == true {
			if Verbose == true {
				log.Printf("[ALL] %s ", target)
			}
			Check(target, "ALL")
		}
	}
}

func main() {
	ParseArguments()

	fmt.Println("SubOver v.1.2              Nizamul Rana (@Ice3man)")
	fmt.Println("==================================================")

	if HostsList == "" {
		fmt.Printf("SubOver: No hosts list specified for testing!")
		fmt.Printf("\nUse -h for usage options\n")
		os.Exit(1)
	}

	InitializeProviders()
	Hosts, err := ReadFile(HostsList)
	if err != nil {
		fmt.Printf("\nread: %s\n", err)
		os.Exit(1)
	}

	Targets = append(Targets, Hosts...)

	hosts := make(chan string, Threads)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(Threads)

	for i := 0; i < Threads; i++ {
		go func() {
			for {
				host := <-hosts
				if host == "" {
					break
				}

				Checker(host)
			}

			processGroup.Done()
		}()
	}

	for _, Host := range Targets {
		hosts <- Host
	}

	close(hosts)
	processGroup.Wait()

	fmt.Printf("\n[~] Enjoy your hunt !\n")
}
