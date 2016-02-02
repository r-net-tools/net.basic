# Load needed libraries
library("XML")
library("bitops")
library("plyr") # rbind.fill

# Transforma una IP ("192.168.0.1") a integer (3232235521)
ip2long <- function(ip) {
    require(bitops)
    # transforma a vector de characters
    ips <- unlist(strsplit(ip, '.', fixed=TRUE))
    # set up a function to bit-shift, then "OR" the octets
    octet <- function(x,y) bitOr(bitShiftL(x, 8), y)
    # Reduce applys a function cumulatively left to right
    Reduce(octet, as.integer(ips))
}

# Convert integer IP address (3232235521)
# to character ("192.168.0.1")
long2ip <- function(longip) {
    require(bitops)
    # set up reversing bit manipulation
    octet <- function(nbits) bitAnd(bitShiftR(longip, nbits), 0xFF)
    # Map applys a function to each element of the argument
    paste(Map(octet, c(24,16,8,0)), sep="", collapse=".")
}

# Check if IP address (string) is in a CIDR range (string)
ip.in.CIDR <- function(ip, cidr)
{
    require(bitops)
    long.ip <- ip2long(ip)
    cidr.parts <- unlist(strsplit(cidr, "/"))
    cidr.range <- ip2long(cidr.parts[1])
    cidr.mask <- bitShiftL(bitFlip(0), (32-as.integer(cidr.parts[2])))
    return(bitAnd(long.ip, cidr.mask) == bitAnd(cidr.range, cidr.mask))
}

getASNinfo <- function(asn, output_file = "data/asn.html")
{
    asn.url <- paste("http://bgp.he.net/",asn,"#_prefixes", sep = "")
    download.file(asn.url, destfile = output_file)
    asn.html <- htmlParse(output_file)
    asn.info <- getNodeSet(asn.html, "//table[@id='table_prefixes4']")
    asn.info <- readHTMLTable(asn.info[[1]])
    asn.info[] <- lapply(asn.info, as.character)
    asn.info
}

whatismyip <- function()
{
    require(rjson)
    fromJSON(readLines("http://api.hostip.info/get_json.php", warn=F))$ip
}

hasIPformat <- function(ip)
{
    b <- as.logical(length(grep("^\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}$", x = ip)))
    if (b == TRUE) 
    {
        k <- unlist(strsplit(ip,".", fixed = TRUE))
        b <- all(sapply(k, function(x) as.integer(x)<256) == TRUE)
    }
    as.logical(b)
}

getIPaddress <- function(hostname)
{
    require(stringr)
    results <- sapply(hostname, function(x) system(paste("nslookup",x), intern=TRUE))
    if (length(results) ==6)
    {
        ip <- str_extract(results[6,], perl("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}"))  
    }
    else{
        if (length(results) > 6)
        {
            ip <- str_extract(results[6:(length(results)-1),], perl("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}"))  
        }
        else ip <- "NA"
    }
    as.character(ip)
}

# Locate IP address using freegeoip.net service
freegeoip <- function(ip, format = ifelse(length(ip)==1,'list','dataframe'))
{
    if (1 == length(ip))
    {
        # a single IP address
        require(rjson)
        url <- paste(c("http://freegeoip.net/json/", ip), collapse='')
        ret <- fromJSON(readLines(url, warn=FALSE))
        if (format == 'dataframe')
            ret <- data.frame(t(unlist(ret)))
        return(ret)
    } else {
        ret <- data.frame()
        for (i in 1:length(ip))
        {
            r <- freegeoip(ip[i], format="dataframe")
            ret <- rbind(ret, r)
        }
        return(ret)
    }
} 

# Parser nmap
parse.nmap <- function(file.input, file.output.header = "")
{
    # Parse input data
    xmlfile = xmlParse(file.input)
    root <- xmlRoot(xmlfile)
    nmap.info <- xmlChildren(root)
    
    # Get scan information
    # scan.info <- as.data.frame(t(xmlAttrs(root)))
    
    # Foreach host
    i = 1
    dns.info <- data.frame()
    nmap.data <- data.frame()
    while (i <= xmlSize(nmap.info))
    {
        if (xmlName(nmap.info[[i]]) == "host")
        {
            host.status <- as.data.frame(t(xmlAttrs(xmlChildren(nmap.info[[i]])$status)))
            names(host.status) <- c("h.state","h.reason","h.reason_ttl")
            host.address <- as.data.frame(t(xmlAttrs(xmlChildren(nmap.info[[i]])$address)))
            if ("hostnames" %in% names(xmlChildren(nmap.info[[i]])) & xmlValue(xmlChildren(nmap.info[[i]])$hostnames) != "\n")
            {
                hostnames <- xmlChildren(xmlChildren(nmap.info[[i]])$hostnames)
                j = 1
                while (j <= length(hostnames))
                {
                    host.ip <- as.character(host.address$addr)
                    host.hostname <- as.data.frame(t(xmlAttrs(hostnames[[j]])))
                    dns.info <- rbind(dns.info, cbind(host.ip, host.hostname))
                    j = j + 1
                }
            }
            if ("ports" %in% names(xmlChildren(nmap.info[[i]])))
            {
                ports <- xmlChildren(xmlChildren(nmap.info[[i]])$ports)
                j = 1
                while (j <= length(ports))
                {
                    if (xmlName(ports[[j]]) == "port")
                    {
                        host.port <- as.data.frame(t(xmlAttrs(ports[[j]])))
                        port.info <- xmlChildren(ports[[j]])
                        port.detail <- cbind(as.data.frame(t(xmlAttrs(port.info$state))),
                                             as.data.frame(t(xmlAttrs(port.info$service))))
                        host.port <- cbind(host.port,port.detail)
                        nmap.data <- rbind.fill(nmap.data, cbind(host.address, host.status, host.port))
                    }
                    j = j + 1
                }
            }
            else
            {
                nmap.data <- rbind.fill(nmap.data, cbind(host.address, host.status))
            }
        }
        i = i + 1
    }
    nmap.data <- unique(nmap.data)
    nmap.data[] <- lapply(nmap.data, as.character)
    dns.info <- unique(dns.info)
    dns.info[] <- lapply(dns.info, as.character)
    
    # Save all results
    #saveRDS(nmap.data, file = paste("output/",file.output.header,"nmap.data.rds",sep = ""))
    #saveRDS(dns.info, file = paste("output/",file.output.header,"info.dns.rds",sep=""))
    
    nmap.data
}
