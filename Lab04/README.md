# Lab 04: Vulnerability Scanning with Nessus

## 1. Mục tiêu
* Tìm hiểu và thực hành sử dụng công cụ kiểm tra và dò quét lỗ hổng bảo mật chuyên nghiệp **Nessus Essentials** trên môi trường Lab
* Phân tích và so sánh sự khác biệt về hiệu quả, độ sâu của kết quả quét giữa hai phương thức: Quét không dùng tài khoản chứng thực (Uncredentialed Scan) và Quét có dùng tài khoản chứng thực (Credentialed Scan)
* Thực hiện cấu hình nâng cao (**Advanced Scan**) nhằm tối ưu hóa tốc độ và giới hạn phạm vi quét vào một nhóm lỗ hổng mục tiêu cụ thể thông qua việc quản lý Plugins
* Nghiên cứu, cài đặt mở rộng và đánh giá công cụ quét lỗ hổng mã nguồn mở hiện đại **Trivy** (Aqua Security) trên các đối tượng: hệ thống tệp (filesystem), kho chứa mã nguồn (repository), và Docker image cũ để phát hiện mã lỗi CVE cũng như rò rỉ thông tin nhạy cảm (secrets)

## 2. Thông tin nhóm thực hiện

- **Nhóm:** 09 – NT101.Q22.1
- **Thành viên:**
  - **Lê Minh Sang (24521518):** thực hiện Câu 1, Câu 2 (50%)
  - **Lê Minh Quang (24521466):** thực hiện Câu 3 (25%)
  - **Phạm Phú Quang (24521478):** thực hiện Câu 4 (25%)

## 3. Nội dung chính các bài tập

### Nhiệm vụ 2.1: Basic Network Scan không dùng tài khoản chứng thực
* **Mô tả & Kết quả**: 
  * **Scan lần 1 (TCP Scan)**: cấu hình dải port từ `1-65535` quét máy mục tiêu Metasploitable 2 không cấp tài khoản xác thực. Kết quả phát hiện tổng cộng **64 nhóm lỗ hổng** bảo mật, trong đó gồm: *9 Critical, 5 High, 22 Medium, 8 Low và 136 Info*. Một số lỗ hổng nghiêm trọng gồm: *VNC Server 'password' Password, Apache Tomcat AJP Connector Request Injection, SSL Version 2 and 3 Protocol Detection, và Bind Shell Backdoor Detection*. Kiểm tra qua Wireshark ghi nhận chuỗi lớn gói tin `TCP SYN` gửi từ Kali sang máy mục tiêu để thực hiện port scanning và nhận về gói `SYN/ACK` từ các cổng mở
  * **Scan lần 2 (TCP + UDP Scan)**: kích hoạt thêm tính năng quét UDP scanner. Tổng số nhóm lỗ hổng hiển thị trên bảng điều khiển tăng lên thành **108 nhóm** (các lỗ hổng mức độ Critical, High, Medium, Low chính vẫn giữ nguyên tương tự lần 1). Phân tích lưu lượng mạng bằng Wireshark xác nhận có sự xuất hiện của các gói tin kiểm tra dịch vụ UDP
* **Công cụ sử dụng**: công cụ *Nessus Essentials* (Template: *Basic Network Scan*), phần mềm *Wireshark*; các file capture tương ứng: `nessus_basic_tcp_capture.pcapng` (Lần 1) và `nessus_tcp_udp_capture.pcapng` (Lần 2)

### Nhiệm vụ 2.2: quét Metasploitable 2 có dùng tài khoản chứng thực
* **Mô tả & Kết quả**: tạo cấu hình quét mới sử dụng Template nâng cao `Credentialed Patch Audit`. Nhóm tiến hành cấu hình thông tin xác thực SSH trực tiếp bằng tài khoản mặc định của máy mục tiêu (`username: msfadmin` / `password: msfadmin`). Kết quả trả về sau khi hoàn thành hiển thị trạng thái `Auth: Pass`. Do có đặc quyền can thiệp và kiểm tra sâu các bản vá nội bộ, cấu hình hệ thống và danh sách phần mềm bên trong, số lượng lỗ hổng phát hiện tăng vượt bậc so với quét không chứng thực: tổng số lỗ hổng tìm thấy tăng từ 64 lên **243 lỗ hổng** (*17 Critical, 88 High, 115 Medium, 9 Low, 58 Info*), đồng thời đưa ra **66 đề xuất khắc phục** (Remediations). Báo cáo cũng đúc kết, phân tích chi tiết bảng so sánh ưu/nhược điểm giữa hai cơ chế quét có chứng thực và không chứng thực
* **Công cụ sử dụng**: công cụ *Nessus Essentials* (Template: *Credentialed Patch Audit*)

### Nhiệm vụ 2.3: Advanced Scan và chỉ bật một plugin cụ thể là NFS Exported Share Information Disclosure
* **Mô tả & Kết quả**: tạo lập cấu hình quét thông qua `Advanced Scan`, giới hạn dải cổng quét duy nhất là cổng `111` (port của dịch vụ portmapper/rpcbind). Nhóm thực hiện tắt toàn bộ các tính năng dò tìm không cần thiết (Ping host, local port enumerators), đồng thời chọn `Disable All` toàn bộ các Plugins mặc định và chỉ `Enable` duy nhất plugin *NFS Exported Share Information Disclosure*. Kết quả scan trả về trạng thái *Completed*. Nhóm đã thực hiện đối chiếu, kiểm chứng thủ công trên Terminal của Kali Linux bằng các công cụ RPC/NFS: lệnh `rpcinfo -p` liệt kê đầy đủ các dịch vụ phụ thuộc và lệnh `showmount -e` phát hiện ra thư mục gốc `/` của Metasploitable 2 đang được chia sẻ công khai (`*`) cho mọi host. Nhóm cũng giải thích chi tiết cơ chế tại sao Nessus phát sinh thêm traffic đến các port dịch vụ phụ thuộc khác (2049, 33479, 52802...) ngoài port 111 ban đầu và đề xuất các biện pháp hạn chế hành vi này
* **Công cụ sử dụng**: công cụ *Nessus Essentials* (Template: *Advanced Scan*), terminal Kali Linux với các lệnh hệ thống `rpcinfo` và `showmount`

### Nhiệm vụ 2.4: chọn một công cụ quét lỗ hổng khác (Trivy)
* **Mô tả & Kết quả**: nghiên cứu và cài đặt thành công công cụ quét bảo mật mã nguồn mở hiện đại **Trivy** do *Aqua Security* phát triển. Nhóm triển khai thực nghiệm quét trên 3 phương diện:
  * **Quét Filesystem**: chạy lệnh quét thư mục `/home`, kết quả không phát hiện lỗ hổng trực tiếp nhưng trả về các dòng log cảnh báo hệ thống
  * **Quét Repository**: thử nghiệm quét trên kho mã nguồn Github, đặc biệt khi quét repo của ứng dụng lỗi `OWASP Juice Shop`, Trivy đã phát hiện và bóc tách thành công rất nhiều thông tin nhạy cảm/khóa bí mật bị lộ (**secrets**)
  * **Quét Docker Image**: thực hiện quét các image Docker cũ, hệ thống báo cáo chi tiết một danh sách lớn các mã định danh lỗ hổng chuẩn hóa (**CVE**). Nhóm lựa chọn và giải thích chi tiết cơ chế hoạt động của 2 mã lỗi điển hình phát hiện ra: `CVE-2019-10082` (lỗi giải phóng vùng nhớ trong xử lý giao thức HTTP/2 của Apache) và `CVE-2021-26691` (lỗi tràn bộ nhớ đệm khi Apache xử lý tiêu đề SessionHeader)
* **Công cụ sử dụng**: công cụ *Trivy*, môi trường *Docker*, nền tảng quản lý mã nguồn *Git/GitHub*

---

## 4. Hướng dẫn chạy chương trình / Thực hiện

### Yêu cầu môi trường
* **Hệ điều hành tấn công/Dò quét**: máy ảo **Kali Linux** (đã được cài đặt sẵn công cụ *Nessus Essentials* chạy tại URL quản trị: `https://localhost:8834`, công cụ *Wireshark*, công cụ *Trivy* và môi trường dịch vụ *Docker*)
* **Hệ điều hành mục tiêu**: máy ảo **Metasploitable 2** (chứa sẵn các cấu hình lỗi dịch vụ mạng cố ý để thử nghiệm)
* **Cấu hình mạng**: cấu hình mạng các máy ảo ở chế độ *Host-only* hoặc *NAT Network* chung một dải mạng để đảm bảo thông suốt kết nối giữa Kali Linux và máy mục tiêu

### Các bước thực hiện cốt lõi

#### Bước 1: thực hiện Basic Network Scan không chứng thực (Nhiệm vụ 2.1)
1. Đăng nhập vào giao diện web điều khiển của Nessus (`https://localhost:8834`)
2. Chọn `New Scan` -> Chọn template `Basic Network Scan`
3. Điền thông tin cấu hình: đặt tên bài quét, nhập IP máy mục tiêu Metasploitable 2. Tại mục *Discovery* -> *Port Scanning*, đặt dải cổng cần quét là `1-65535`
4. *(Đối với lần scan thứ 2)*: vào cấu hình điều chỉnh bật thêm tính năng quét cổng **UDP**
5. Bật công cụ *Wireshark* trên Kali Linux bắt gói tin trên card mạng tương ứng, sau đó nhấn nút `Launch` trên Nessus để chạy quét. Đợi tiến trình hoàn thành để phân tích kết quả lỗ hổng và bộ lọc traffic

#### Bước 2: thực hiện quét có tài khoản chứng thực (Nhiệm vụ 2.2)
1. Tại màn hình chính Nessus, chọn `New Scan` -> Chọn template `Credentialed Patch Audit`
2. Cấu hình các thông tin cơ bản (Tên, Target IP)
3. Di chuyển sang tab `Credentials` -> Chọn danh mục xác thực `SSH`. Thay đổi phương thức xác thực thành `Password` và nhập chính xác thông tin đăng nhập: `Username: msfadmin` và `Password: msfadmin`
4. Nhấn `Save` và chọn `Launch` để bắt đầu tiến trình quét. Đợi trạng thái chuyển sang `Completed`, tiến hành đọc bảng so sánh số lượng lỗ hổng gia tăng

#### Bước 3: Thực hiện cấu hình Advanced Scan lọc duy nhất một Plugin (Nhiệm vụ 2.3)
1. Tạo scan mới bằng cách chọn cấu hình template `Advanced Scan`
2. Tại mục *Discovery* -> *Port Scanning*, chỉ định duy nhất cổng quét là `111`. Tiến hành tắt các tính năng *Ping to remote host* và *local port enumerators* để tăng tốc độ
3. Di chuyển sang tab `Plugins` -> Click chọn nút `Disable All` để vô hiệu hóa tất cả các nhóm plugin mặc định
4. Sử dụng thanh tìm kiếm để tìm cụm từ khóa liên quan đến dịch vụ RPC/NFS, tìm đến đúng Plugin có tên `NFS Exported Share Information Disclosure` và chuyển trạng thái của nó sang `Enabled`. Lưu và chọn `Launch`
5. Sau khi quét xong, mở Terminal trên Kali Linux chạy song song hai lệnh kiểm chứng thủ công:
   ```bash
   rpcinfo -p <Địa_chỉ_IP_Metasploitable>
   showmount -e <Địa_chỉ_IP_Metasploitable>
