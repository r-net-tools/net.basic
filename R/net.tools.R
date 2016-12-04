#' ip2long
#' Transforma una IP "192.168.0.1" a integer 3232235521
#' 
#' @param ip 
#' @return
#' @export
#' @examples
#' ip <- ip2long("192.168.0.1")
ip2long <- function(ip) {
    # transforma a vector de characters
    ips <- unlist(strsplit(ip, '.', fixed = TRUE))
    # set up a function to bit-shift, then "OR" the octets
    octet <- function(x,y) bitops::bitOr(bitops::bitShiftL(x, 8), y)
    # Reduce applys a function cumulatively left to right
    return(Reduce(octet, as.integer(ips)))
}

#' long2ip Convert integer IP address 3232235521 to character "192.168.0.1"
#'
#' @param longip 
#' @return
#' @export
#' @examples
long2ip <- function(longip) {
    # set up reversing bit manipulation
    octet <- function(nbits) bitops::bitAnd(bitops::bitShiftR(longip, nbits), 0xFF)
    # Map applys a function to each element of the argument
    return(paste(Map(octet, c(24,16,8,0)), sep = "", collapse = "."))
}

#' ip_in_CIDR
#' Check if IP address (string) is in a CIDR range (string)
#'
#' @param ip 
#' @param cidr 
#' @return
#' @export
#' @examples
ip_in_CIDR <- function(ip, cidr) {
    long.ip <- ip2long(ip)
    cidr.parts <- unlist(strsplit(cidr, "/"))
    cidr.range <- ip2long(cidr.parts[1])
    cidr.mask <- bitops::bitShiftL(bitops::bitFlip(0), (32 - as.integer(cidr.parts[2])))
    return(bitops::bitAnd(long.ip, cidr.mask) == bitops::bitAnd(cidr.range, cidr.mask))
}

#' whatismyip
#'
#' @return
#' @export
#'
#' @examples
whatismyip <- function() {
    return(
      rjson::fromJSON(
        readLines("http://api.hostip.info/get_json.php", warn = F))$ip
    )
}

#' hasIPformat
#'
#' @param ip 
#'
#' @return
#' @export
#'
#' @examples
hasIPformat <- function(ip) {
    b <- as.logical(length(grep("^\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}$", x = ip)))
    if (b == TRUE) 
    {
        k <- unlist(strsplit(ip,".", fixed = TRUE))
        b <- all(sapply(k, function(x) as.integer(x) < 256) == TRUE)
    }
    return(as.logical(b))
}

#' getIPaddress
#'
#' @param hostname 
#'
#' @return
#' @export
#'
#' @examples
getIPaddress <- function(hostname) {
    results <- sapply(hostname, function(x) system(paste("nslookup",x), intern = T))
    if (length(results) == 6)
    {
        ip <- stringr::str_extract(results[6,], stringr::perl("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}"))  
    }
    else{
        if (length(results) > 6)
        {
            ip <- stringr::str_extract(results[6:(length(results) - 1),], stringr::perl("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}"))  
        }
        else ip <- "NA"
    }
    return(as.character(ip))
}

#' freegeoip
#' Locate IP address using freegeoip.net service
#' 
#' @param ip 
#' @param format 
#'
#' @return
#' @export
#'
#' @examples
freegeoip <- function(ip, format = ifelse(length(ip) == 1,'list','dataframe')) {
    if (1 == length(ip))
    {
        # a single IP address
        url <- paste(c("http://freegeoip.net/json/", ip), collapse = '')
        ret <- rjson::fromJSON(readLines(url, warn = F))
        if (format == 'dataframe')
            ret <- data.frame(t(unlist(ret)))
        return(ret)
    } else {
        ret <- data.frame()
        for (i in 1:length(ip))
        {
            r <- freegeoip(ip[i], format = "dataframe")
            ret <- rbind(ret, r)
        }
        return(ret)
    }
} 


#' hex2ip
#' Transform an 8 bytes hexadecimal string to ip address
#'
#' @param hex 
#'
#' @return
#' @export
#'
#' @examples
#' ip <- hex2ip("c0a80001")
hex2ip <- function(hex){
  if(nchar(hex) == 8){
    chunks <- lapply(seq(1,nchar(hex),2), function(i) substr(hex, i, i+1))
    ip <- paste(strtoi(chunks, 16), sep = "", collapse = ".")
  }
  else ip <- "NA"
  return(ip)
}

#' ip2hex
#' Transform an ip address to hexadecimal
#'
#' @param ip 
#'
#' @return
#' @export
#'
#' @examples
#' hex <- ip2hex("192.168.0.1")
ip2hex <- function(ip){
  chunks <- strtoi(unlist(strsplit(ip, '.', fixed = TRUE)))
  format <- lapply(chunks, function(i) sprintf("%02x",as.hexmode(i)))
  return(paste(format, sep = "", collapse = ""));
}
