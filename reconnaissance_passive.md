# Passive Reconnaissance / OSINT

## Wayback URLs

To dump all of the links that are saved in Wayback Machine, we can use the tool called waybackurls.
 - https://github.com/tomnomnom/waybackurls

## Google Dorks

By crafting specific search queries, known as Google Dorks, you can find information that wasn’t meant to be public. These queries can pull up everything from exposed administrative directories to logs containing passwords and indices of sensitive directories. For example:

- To find administrative panels: `site:example.com inurl:admin`
- To unearth log files with passwords: `filetype:log "password" site:example.com`
- To discover backup directories: `intitle:"index of" "backup" site:example.com`
