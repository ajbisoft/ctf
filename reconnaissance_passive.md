# Passive Reconnaissance / OSINT

## Wayback URLs

To dump all of the links that are saved in Wayback Machine, we can use the tool called waybackurls.
 - https://github.com/tomnomnom/waybackurls

## Google Dorks

By crafting specific search queries, known as Google Dorks, you can find information that wasn’t meant to be public. These queries can pull up everything from exposed administrative directories to logs containing passwords and indices of sensitive directories. 

### Google Dork Basic commands

| Command | Description | Syntax | Example |
| ------- |:-----------:|--------|---------|
| After | Finds content indexed after a specific date | after:[date] | `after:2022-01-01` |
| Allinurl | Finds pages with multiple keywords in the URL | allinurl:[keywords] | `allinurl:python programming` |
| Allintitle | Finds pages with multiple keywords in the title | allintitle:[keywords] | `allintitle:machine learning tutorial` |
| AROUND(X) | Finds pages where two terms are within a specified number of words from each other | [term1] AROUND(X) [term2] | `artificial intelligence AROUND(10) ethics` |
| Before | Finds content indexed before a specific date	| before:[date] | `before:2020-06-15` |
| Define | Displays the definition of a word or phrase | define:[word or phrase] | `define:quantum computing` |
| Ext | Finds a specific file extension | ext:[file extension] | `ext:doc` |
| Filetype | Locates specific file types like PDF or XLS | filetype:[file type] | `filetype:pdf annual report` |
| Inanchor | Searches for keywords within the anchor text of links on a web page | inanchor:[keyword] | `inanchor:buy now` |
| Info | Provides details about a website, including cache and similar pages | info:[URL] | `info:example.com` |
| Intext | Searches for keywords within the body text of a web page | intext:[keyword] | `intext:data science` |
| Intitle | Finds a keyword within a web page's title | intitle:[keyword] | `intitle:blockchain` |
| Inurl	| Searches for a keyword within a URL | inurl:[keyword] | `inurl:login` |
| Link | Finds web pages linking to a specific URL | link:[URL] | `link:wikipedia.org` |
| Map | Shows the map of a location or address | map:[location or address] | `map:1600 Amphitheatre Parkway, Mountain View, CA` |
| Numrange | Searches for numbers within a specified range | [number]..[number] | `50..100` |
| Phonebook | Searches for phone numbers and contact information for a person or business | phonebook:[name or business] | `phonebook:John Doe` |
| Related | Displays pages related to a specific URL | related:[URL] | `related:nytimes.com` |
| Site | Finds results on a specific website or domain | site:[domain] | `site:bbc.com climate change` |

### Other examples:

- To find administrative panels: `site:example.com inurl:admin`
- To unearth log files with passwords: `filetype:log "password" site:example.com`
- To discover backup directories: `intitle:"index of" "backup" site:example.com`

## Subdomain enumeration

### subfinder

`subfinder -d <target> -all > domains1.txt`

### crt.sh

Go to https://crt.sh website and enumerate for issued certificates

### assetfinder

`assetfinder <target> -subs-only > domains2.txt`

### chaos.projectdiscovery.io

Use public bug bounty data from https://chaos.projectdiscovery.io

### Sort outputs

Sort outputs from previous commands to make a unique list of domains:

`sort -u domain1.txt domain2.txt > domains.txt`

### Check for live domains

`cat domains.txt | httpx -sc > status.txt`

### Use ffuf

Ie. <subdomain> wordlist can be: `/usr/share/seclists/Discovery/DNS/cubdomains-top1million-20000.txt`.

`ffuf -u http://FUZZ.<target> -w <subdomain_wordlist> -o fuff.txt`

### subzy

Can find somains that ar vulnerable for domain takeover (ie. to be used in phishing campaign)

`subzy run --targets domains.txt`

## Other sources for passive recon

- **Websites** provide attackers with information on organizational structure and technologies and alert them to potential weak spots. For example, attackers can exploit outdated content management systems (CMS) on company websites and use unpatched vulnerabilities to access internal databases.

- **Domain registrations** equip attackers with extensive information on the domain owner. This information can be used to launch phishing or impersonation attacks. For instance, an attacker can find the personal contact details of domain owners and send phishing emails to steal their login credentials.

- **Social media** enables quick and easy access to data on employee roles, company culture, and other public information. Attackers can potentially use this information for spear-phishing or social engineering. For example, an attacker may identify a company's leadership personnel on LinkedIn and send them personalized phishing emails to trick them into revealing sensitive data.

- **Public records**, such as business filings or legal documents, can give attackers insights into a company's operations and key personnel. They can use this information to plan targeted attacks. For example, attackers can gather details about company executives from public filings, such as government databases, and launch a spear-phishing campaign against them.

- **Job postings** often reveal information on the technologies and systems used by the company that attackers can exploit if there are known vulnerabilities. For instance, an attacker might see that a company was using specific software from a job posting and use a known vulnerability in that software to attack.

- **Online forums and communities** provide a portal to extensive insider information and industry trends on online forums. Attackers might use this knowledge to exploit known issues or for social engineering. For example, an attacker can find details on an organization's recent security problems on a forum and leverage it to create a targeted phishing attack.
