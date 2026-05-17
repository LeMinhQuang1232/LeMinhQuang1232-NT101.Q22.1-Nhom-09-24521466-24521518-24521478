# Lab 05: Khai thác tường lửa trong Linux & Triển khai Web Proxy, VPN

## 1. Mục tiêu
- Tìm hiểu nguyên lý hoạt động, cơ chế kiểm soát và thực hành cấu hình chính sách bảo mật (Firewall Rules) trên công cụ **Packet Filter Firewall (pfSense)** trong môi trường mạng ảo hóa
- Phân tích và thực nghiệm các kỹ thuật vượt qua sự kiểm soát của tường lửa mạng truyền thống (**Firewall Bypassing**) sử dụng cơ chế đóng gói và mã hóa giao thức thông qua **SSH Tunneling** (Local Port Forwarding và Dynamic Port Forwarding/SOCKS Proxy)
- Triển khai giải pháp **Web Proxy (Application Firewall)** bằng dịch vụ **Squid Proxy**, kết hợp viết kịch bản **URL Rewriting** bằng ngôn ngữ Perl để can thiệp sâu, chuyển hướng và thay đổi nội dung trang web phân phối đến người dùng cuối ở tầng ứng dụng
- Nghiên cứu cơ chế mạng riêng ảo **VPN (Virtual Private Network)**, so sánh các giao thức phổ biến (OpenVPN, IPsec, L2TP) và cấu hình thành công hệ thống **OpenVPN Server** trên pfSense để thiết lập kênh truyền an toàn xuyên qua tường lửa cho các máy khách ngoài vùng WAN

## 2. Thông tin nhóm thực hiện
- **Nhóm:** 09 – NT101.Q22.1
- **Thành viên:**
  - **Lê Minh Sang (24521518)** 
  - **Lê Minh Quang (24521466)** 
  - **Phạm Phú Quang (24521478)**

## 3. Nội dung chi tiết bài thực hành
### 3.1. Sơ đồ kiến trúc mạng tổng quan
Mô hình thực hành được xây dựng độc lập trên nền tảng ảo hóa với cấu trúc 3 thực thể phân tách rõ ràng qua tường lửa mạng:
  * Tường lửa pfSense: đóng vai trò Gateway trung tâm điều phối và lọc lưu lượng:
    * Interface WAN (NAT Network): `10.0.125.3/24` 
    * Interface LAN (Host-Only): `192.168.125.3/24` 
  * VM A (Ubuntu - mạng nội bộ LAN): `192.168.125.4/24`, cấu hình Default Gateway trỏ trực tiếp về IP LAN của pfSense (`192.168.125.3`)
  * VM B (Ubuntu - vùng ngoài WAN): `10.0.125.4/24`, đóng vai trò máy chủ bên ngoài, cài đặt sẵn các dịch vụ mạng như `telnetd`, `openssh-server`

### 3.2. Cấu hình chính sách bảo vệ trên Firewall (Nhiệm vụ 2)
Nhóm thực hiện thiết lập các bộ lọc luật nghiêm ngặt tại tab **Firewall -> Rules -> LAN** trên giao diện pfSense để quản lý toàn bộ luồng dữ liệu đi ra từ mạng nội bộ:

* Rule 1: chặn ICMP (Ping): cấu hình rule mức `Block`, Protocol `ICMP`, Source `LAN subnets`, Destination `Host 10.0.125.4` (VM B). Kết quả kiểm tra bằng lệnh `ping` từ VM A báo trạng thái timeout, gói tin ICMP bị tường lửa hủy hoàn toàn tại tầng Network
* Rule 2: chặn HTTP (Port 80): cấu hình rule `Block`, Protocol `TCP`, Source `LAN subnets`, Destination `any`, Destination Port Range `HTTP (80)`. Kiểm tra bằng lệnh `telnet 10.0.125.4 80` từ VM A ghi nhận kết nối bị treo hoặc từ chối (Connection timeout)
* Rule 3: chặn kết nối Telnet (Port 23): cấu hình rule `Block`, Protocol `TCP`, Source `LAN subnets`, Destination `any`, Destination Port Range `Telnet (23)`[cite: 649, 654]. Kết quả là lệnh `telnet 10.0.125.4` phát ra từ máy nội bộ không thể thiết lập bắt tay 3 bước
* Rule 4: chặn mạng xã hội qua tên miền (Facebook & Youtube): do nhà cung cấp dịch vụ thay đổi IP liên tục, nhóm triển khai thông qua tính năng **Firewall -> Aliases**. Tạo một Alias kiểu Host, nhập các FQDN mục tiêu như `facebook.com` và `youtube.com`. Áp dụng rule `Block` giao thức `TCP/UDP` hướng tới đích là Alias này. Kết quả trên trình duyệt Firefox của VM A, mọi nỗ lực truy cập vào các trang này đều bị chặn đứng và trả về thông báo lỗi Timeout

### 3.3. Thực nghiệm kỹ thuật vượt tường lửa - Firewall Bypassing (Nhiệm vụ 3)
Phần này chứng minh lỗ hổng của các tường lửa thế hệ cũ khi chỉ lọc dựa trên Port/IP truyền thống mà không phân tích sâu gói tin:

- SSH Local Port Forwarding: sử dụng lệnh khởi tạo tunnel từ VM A kết nối dịch vụ SSH đến VM B, đồng thời ánh xạ cổng dịch vụ:
  ```bash
  ssh -L 8000:localhost:23 user@10.0.125.4
  ```

  Khi VM A gọi lệnh telnet localhost 8000, lưu lượng Telnet dạng bản rõ (plaintext) thay vì đi trực tiếp ra ngoài qua cổng 23 (vốn bị chặn) thì sẽ được công cụ SSH Client tại VM A đón chặn, thực hiện mã hóa toàn bộ dữ liệu và đóng gói nó vào luồng dữ liệu của giao thức SSH (Port 22)  

  Do pfSense cho phép cổng SSH outbound hoạt động, gói tin này đi qua tường lửa hoàn toàn hợp lệ. Khi tới VM B, dịch vụ SSH Server giải mã luồng traffic này và chuyển tiếp nó đến cổng 23 nội bộ của chính nó

- Dynamic Port Forwarding (SOCKS Proxy): nhóm tạo ra một mạng trung gian động bằng lệnh:
  ```bash
  ssh -D 9000 -C user@10.0.125.4
  ```

  Lệnh này mở một cổng lắng nghe SOCKS Proxy tại cổng 9000 ngay trên máy VM A. Sau khi cấu hình trình duyệt Firefox trỏ mạng SOCKS v5 về 127.0.0.1:9000, mọi yêu cầu duyệt web (bao gồm cả truy cập www.facebook.com) đều được đóng gói qua kênh mã hóa SSH đến VM B. Lúc này VM B sẽ đóng vai trò truy vấn DNS và lấy dữ liệu thay cho VM A. Kết quả là VM A có thể lướt Facebook bình thường bất chấp quy tắc chặn FQDN trước đó của tường lửa

- Giải pháp ngăn chặn: nếu cấu hình tường lửa chặn triệt để cổng 22, các tunnel tiêu chuẩn này lập tức bị vô hiệu hóa. Tuy nhiên, để tối ưu, nhóm đề xuất triển khai các hệ thống phát hiện xâm nhập IDS/IPS (Snort/Suricata) nhằm phân tích hành vi phiên mạng (phát hiện kết nối SSH duy trì bất thường, dung lượng lớn nhưng không phát sinh ký tự gõ lệnh Terminal) hoặc áp dụng tính năng Deep Packet Inspection (DPI) trên các thiết bị tường lửa thế hệ mới (NGFW) để bóc tách hành vi Tunneling ẩn

### 3.4. Triển khai Web Proxy Application Firewall bằng Squid (Nhiệm vụ 4)
Để quản lý nội dung web ở tầng ứng dụng, dịch vụ Squid Proxy được cài đặt trên cổng mạng 3128. Khi máy VM A được thiết lập cấu hình đi qua Proxy này, nó gửi toàn bộ dữ liệu HTTP đến cổng 3128 của máy chủ Proxy, vượt qua được quy tắc chặn cổng 80 trực tiếp của pfSense  

Nhóm áp dụng cơ chế URL Rewriting bằng cách kích hoạt tham số url_rewrite_program trong file cấu hình squid.conf trỏ về một đoạn script viết bằng Perl (script.pl). Chương trình Perl này chạy một vòng lặp liên tục để đọc dữ liệu URL nhận từ Squid qua chuẩn đầu vào stdin và ghi URL đã xử lý ra stdout. Việc đặt cơ chế autoflush $|=1 giúp dữ liệu không bị nghẽn ở bộ đệm, phản hồi tức thì cho Proxy. Nhóm đã tùy biến mã nguồn kịch bản xử lý theo hai cấp độ:
- Kịch bản 1 - Chuyển hướng trang cụ thể hiển thị ảnh cảnh báo:
Khi phát hiện chuỗi URL đầu vào chứa từ khóa mạng mục tiêu example.com, kịch bản lập tức thay thế URL trang bằng một liên kết trực tiếp dẫn tới một file định dạng ảnh cảnh báo dừng lại (stop_warning.png). Người dùng truy cập trang web này sẽ chỉ nhận về một bức ảnh cảnh báo duy nhất trên màn hình

- Kịch bản 2 - Thay thế toàn bộ hình ảnh trên không gian Internet:
Nhóm sử dụng bộ lọc biểu thức chính quy (Regular Expression) nâng cao để quét tìm tất cả các liên kết URL có phần mở rộng kết thúc bằng các định dạng đồ họa phổ biến:
  ```bash
  if ($url =~ m/\.(jpg|jpeg|png|gif|svg|webp)(\?.*)?$/i)
  ```
  Nếu URL khớp với định dạng ảnh, script tự động rewrite thành đường dẫn URL của một bức ảnh tùy chọn do nhóm chuẩn bị sẵn. Kết quả thực nghiệm vô cùng trực quan: Khi máy khách VM A lướt bất kỳ trang web tin tức hay diễn đàn nào, toàn bộ các thành phần hình ảnh gốc của trang web đó đều bị Squid Proxy thay thế đồng loạt bằng bức ảnh chỉ định của nhóm

### 3.5. Cấu hình mạng riêng ảo VPN bảo mật qua Tường lửa (Nhiệm vụ 5)
- Đánh giá các giải pháp: Nhóm thực hiện nghiên cứu so sánh 3 giao thức cốt lõi được tích hợp trên pfSense:
  * OpenVPN: hoạt động ở tầng ứng dụng, sử dụng mã hóa SSL/TLS cực kỳ mạnh mẽ, có khả năng cấu hình đổi cổng mạng linh hoạt (ví dụ chạy trên TCP 443) để vượt tường lửa/NAT hoàn hảo
  * IPsec: hoạt động ở tầng Network, tính chuẩn hóa cao, bảo mật mạnh mẽ nhưng cấu hình rất phức tạp và dễ gặp lỗi đồng bộ khi đi qua các thiết bị thực hiện NAT mạng
  * L2TP/IPsec: dễ triển khai, được tích hợp sẵn trên các nền tảng hệ điều hành di động, tuy nhiên bản thân giao thức L2TP không có tính năng mã hóa mà phải mượn lớp bảo mật IPsec bọc bên ngoài
- Kết quả cấu hình: nhóm quyết định triển khai giải pháp OpenVPN Server. Để kết nối thành công từ mạng ngoài, trước hết nhóm tắt quy tắc chặn mặc định Block private networks trên Interface WAN của pfSense. Sau đó thực hiện tạo mới một cơ quan chứng thực Certificate Authority (MyVPN-CA) và một Server Certificate mã hóa 2048-bit từ trình quản lý chứng chỉ hệ thống. Cấu hình dịch vụ OpenVPN Server lắng nghe tại cổng UDP 1194, cấp dải mạng ảo Tunnel Network là 10.8.0.0/24 và khai báo định tuyến cho phép truy cập vào dải mạng nội bộ Local Network 192.168.125.0/24. Tạo tài khoản định danh hệ thống, export file cấu hình .ovpn cấp cho máy trạm. Kết quả thực nghiệm: Khi kích hoạt OpenVPN Client trên máy VM B, hệ thống thiết lập thành công kênh truyền mã hóa bảo mật, máy VM B được cấp IP ảo 10.8.0.x và có thể thiết lập giao tiếp, ping và trao đổi dữ liệu trực tiếp với máy nội bộ VM A (192.168.125.4) xuyên qua tường lửa pfSense mà không bị cản trở

## 4. Hướng dẫn từng bước cấu hình và triển khai chi tiết
Do bài thực hành này tập trung hoàn toàn vào việc cấu hình hệ thống dịch vụ trực tiếp, dưới đây là các bước thao tác và câu lệnh cụ thể trên các máy trạm để tái dựng lại môi trường Lab

### 4.1. Thiết lập các bộ lọc trên giao diện Quản trị pfSense
- Từ máy VM A, khởi động trình duyệt và đăng nhập giao diện WebGUI: https://192.168.125.3 (Tài khoản mặc định: admin / pfsense)
- Cấu hình Aliases chặn mạng xã hội: vào Firewall -> Aliases -> IP, bấm Add. Đặt tên Social_Networks, mục Type chọn Host(s). Tại các ô giá trị, điền chính xác facebook.com và youtube.com. Nhấn Save và Apply Changes
- Thêm các quy tắc lọc Rule: di chuyển đến mục Firewall -> Rules, chọn tab LAN. Tiến hành thêm mới (Add lên trên) các quy tắc với thứ tự ưu tiên từ trên xuống dưới:
  * Chặn Ping: Action: Block | Protocol: ICMP | ICMP Subtypes: Any | Source: LAN subnets | Destination: Single host or alias | Nhập 10.0.125.4
  * Chặn HTTP: Action: Block | Protocol: TCP | Source: LAN subnets | Destination: Any | Destination Port Range: từ HTTP (80) đến HTTP (80)
  * Chặn Telnet: Action: Block | Protocol: TCP | Source: LAN subnets | Destination: Any | Destination Port Range: từ Telnet (23) đến Telnet (23)
  * Chặn MXH: Action: Block | Protocol: TCP/UDP | Source: LAN subnets | Destination: Single host or alias | Nhập tên BLOCK_FB_YT
- Bấm nút Apply Changes ở góc trên cùng để kích hoạt toàn bộ các luật bảo mật vừa tạo

### 4.2. Câu lệnh triển khai Kỹ thuật Vượt tường lửa từ Terminal VM A
- Khởi tạo kênh Local Forwarding bypass Telnet:  
  Mở Terminal trên máy VM A, thực hiện gõ câu lệnh sau để tạo đường truyền SSH bọc gói tin Telnet sang máy vùng WAN:
  ```bash
  ssh -L 8000:localhost:23 user@10.0.125.4
  ```
  Nhập mật khẩu xác thực tài khoản SSH của máy VM B để duy trì phiên kết nối. Giữ nguyên Terminal này. Mở một tab Terminal mới trên máy VM A và gõ lệnh sau để truy cập dịch vụ từ xa thông qua cổng nội bộ:
  ```bash
  telnet localhost 8000
  ```

- Khởi tạo Dynamic Port Forwarding (SOCKS Proxy) bypass Web Filter:
  Tại Terminal máy VM A, gõ lệnh khởi tạo SOCKS Server:
  ```bash
  ssh -D 9000 -C user@10.0.125.4
  ```
  Vào trình duyệt Firefox trên VM A, mở Settings -> Network Settings -> Settings.... Tích chọn mục Manual proxy configuration. Tại ô SOCKS Host, nhập 127.0.0.1 và Port 9000. Đảm bảo tích chọn phiên bản SOCKS v5 và tùy chọn Proxy DNS when using SOCKS v5 để chuyển giao hoàn toàn quyền truy vấn tên miền cho đầu ra. Bấm OK để bắt đầu duyệt web vượt rào bảo mật

### 4.3. Cài đặt Squid Proxy và Cấu hình Script Perl trên máy VM B
- Cài đặt gói dịch vụ Squid Proxy trên máy chủ VM B:
  ```bash
  sudo apt update && sudo apt install squid -y
  ```

- Tạo file kịch bản điều hướng nội dung bằng Perl tại thư mục hệ thống:
  ```bash
  sudo nano /etc/squid/script.pl
  ```

- Mã nguồn chi tiết dành cho Script chuyển hướng website example.com (Nhiệm vụ 4.3):  
  Dán đoạn mã nguồn sau vào file text:
  ```Perl
  #!/usr/bin/perl
  use strict;
  use warnings;

  # Kích hoạt tính năng giải phóng bộ đệm ngay lập tức (Autoflush)
  $| = 1;

  while (<>) {
    my @parts = split(/\s+/, $_);
    my $url = $parts[0];

    if ($url =~ /example\.com/) {
        # Chuyển hướng người dùng sang một ảnh cảnh báo công khai
        print "OK url=[https://images.squarespace-cdn.com/content/v1/5526cf6ee4b0dc6870c63c95/1501708173491-0S0QZ8QNZTFEIE96W7T4/stop-sign.png](https://images.squarespace-cdn.com/content/v1/5526cf6ee4b0dc6870c63c95/1501708173491-0S0QZ8QNZTFEIE96W7T4/stop-sign.png)\n";
    } else {
        # Giữ nguyên URL ban đầu của yêu cầu truy cập
        print "\n";
      }
  }
  ```

- Mã nguồn chi tiết dành cho Script thay thế tất cả hình ảnh duyệt web (Nhiệm vụ 4.4):  
  Nếu muốn chạy bài toán thay thế mọi định dạng ảnh, sửa nội dung file kịch bản thành:
  ```Perl
  #!/usr/bin/perl
  use strict;
  use warnings;

  $| = 1;

  while (<>) {
    my @parts = split(/\s+/, $_);
    my $url = $parts[0];

    # Biểu thức chính quy kiểm tra định dạng đuôi mở rộng của tệp hình ảnh
    if ($url =~ m/\.(jpg|jpeg|png|gif|svg|webp)(\?.*)?$/i) {
        # Thay thế toàn bộ hình ảnh bằng link hình ảnh tùy chọn dưới đây
        print "OK url=[https://upload.wikimedia.org/wikipedia/commons/thumb/1/15/UIT_logo.png/600px-UIT_logo.png](https://upload.wikimedia.org/wikipedia/commons/thumb/1/15/UIT_logo.png/600px-UIT_logo.png)\n";
    } else {
        print "\n";
      }
  }
  ```
- Cấp quyền thực thi cho tệp kịch bản Perl vừa tạo:
  ```bash
  sudo chmod +x /etc/squid/script.pl
  ```

- Cấu hình tích hợp tệp kịch bản vào tệp dịch vụ Squid:
  ```bash
  sudo nano /etc/squid/squid.conf
  ```  
  Tìm và thêm vào cuối file tệp cấu hình các dòng tham số sau để cấp đặc quyền định tuyến:
  ```Plaintext
  url_rewrite_program /etc/squid/script.pl
  url_rewrite_children 5
  http_access allow all
  ```
- Khởi động lại dịch vụ Squid Proxy để áp dụng cấu hình mới:
  ```bash
  sudo systemctl restart squid
  ```

### 4.4. Thao tác thiết lập kết nối Client OpenVPN trên máy VM B
Sau khi thực hiện export file cấu hình dạng .ovpn từ giao diện quản trị của pfSense và chuyển tệp cấu hình đó sang máy khách VM B, thực hiện các lệnh sau trên terminal VM B để bắt đầu kích hoạt kết nối mạng riêng ảo:
- Cài đặt ứng dụng OpenVPN Client:
  ```bash
  sudo apt update && sudo apt install openvpn -y
  ```
- Di chuyển thư mục chứa file cấu hình đã tải về từ VM A sang VM B và tiến hành chạy lệnh thiết lập kênh truyền:
  ```bash
  scp pfSense-UDP4-1194-vpnuser-config.ovpn user@10.0.125.4:home/user/
  ```
- Nhập thông tin tài khoản đăng nhập Username và Password của tài khoản vpnuser đã thiết lập khi được yêu cầu trên Terminal
- Qua VM B kiểm tra xem file đã được chuyển qua chưa nếu đã có bắt đầu Kiểm tra tính thông suốt bằng cách ping trực tiếp tới IP máy nội bộ: ping 192.168.125.4

## 5. Kết luận bài học kinh nghiệm rút ra
- Về cơ chế tường lửa: hiểu rõ nguyên lý hoạt động lọc gói tin theo thứ tự (Top-Down) dựa trên các bộ tham số IP nguồn/đích, cổng dịch vụ mạng và giao thức của Packet Filter Firewall. Tuy nhiên, phương pháp lọc truyền thống này bộc lộ điểm yếu lớn khi không kiểm soát được các kỹ thuật bọc lưu lượng (Protocol Encapsulation) tinh vi
- Về kỹ thuật Tunneling: thực chứng được sức mạnh của cơ chế mã hóa SSH Tunneling. Toàn bộ dữ liệu của một giao thức bị cấm (như Telnet, HTTP mạng xã hội) có thể dễ dàng đi xuyên qua hàng rào phòng thủ của tường lửa bằng cách ẩn mình dưới danh nghĩa của các gói tin mã hóa hợp lệ thuộc cổng 22. Điều này đặt ra yêu cầu cấp thiết phải cấu hình tường lửa đi kèm các luật kiểm soát chặt chẽ luồng dữ liệu Outbound kết hợp với các hệ thống phân tích sâu DPI
- Về hệ thống Web Proxy và VPN: việc làm chủ công cụ Squid Proxy giúp quản lý ứng dụng web hiệu quả, có thể viết mã can thiệp trực tiếp vào dữ liệu luồng duyệt web của người dùng cuối. Đồng thời, giải pháp OpenVPN cung cấp một kênh truyền bảo mật cao, linh hoạt vượt qua rào cản NAT để thiết lập kết nối an toàn từ xa, phục vụ đắc lực cho nhu cầu làm việc và quản trị hệ thống an toàn thông tin
