# Lab 03: Hàm băm và chữ kỹ số

## 1. Mục tiêu
Lab03 tập trung vào việc tìm hiểu lý  thuyết và thực hành các khái niệm cốt lõi liên quan đến hệ mật mã hóa công khai RSA, các hàm băm phổ biến (MD5, SHA-1) và quy trình ứng dụng chữ ký số để xác thực chứng chỉ số X.509 trong thực tế

Mục tiêu chính là nắm vững:
- **Hệ mật mã hóa công khai RSA:** hiểu nguyên lý và tự triển khai thuật toán sinh cặp khóa (Public/Private Key), thực hiện mã hóa/giải mã dữ liệu số, chuỗi văn bản và xử lý bẻ khóa/giải mã các định dạng bản mã khác nhau (Base64, Hex, Nhị phân)
- **Tính chất an toàn của Hàm băm:** thực nghiệm và phân tích hiện tượng xung đột/va chạm hàm băm (Collision) trên thực tế của các giải thuật mã hóa cũ như MD5 và SHA-1
- **Tấn công tạo xung đột hàm băm:** sử dụng thành thạo công cụ chuyên dụng md5collgen để tự sinh ra các cặp tệp tin có nội dung hoàn toàn khác nhau nhưng sở hữu cùng một giá trị băm MD5 từ một tệp tiền tố (prefix file)
- **Hạ tầng khóa công khai (PKI) và Chứng chỉ số:** áp dụng bộ công cụ OpenSSL kết hợp lập trình Python để thực hiện quy trình kiểm tra và xác thực chữ ký số thủ công trên một chứng chỉ SSL/TLS X.509 thực tế của website

## 2. Thông tin nhóm thực hiện
- **Nhóm:** 09 – NT101.Q22.1
- **Thành viên:**
  - **Lê Minh Sang (24521518):** thực hiện Câu 2 (25%)
  - **Lê Minh Quang (24521466):** thực hiện Câu 3, Câu 4 (50%)
  - **Phạm Phú Quang (24521478):** thực hiện Câu 1 (25%)
 
## 3. Nội dung chính các bài tập
  
### Nhiệm vụ 2.1: hệ mật mã khóa công khai RSA
- **Mô tả:** lập trình thuật toán RSA bằng ngôn ngữ Python từ các hàm toán học cơ bản (Euclid mở rộng tìm nghịch đảo mô-đun). Thực hiện sinh cặp khóa với cả số nguyên nhỏ và số nguyên lớn (hệ thập phân lẫn thập lục phân); kiểm nghiệm tính bảo mật và xác thực; tiến hành thử nghiệm giải mã thành công 4 chuỗi bản mã đề bài cho trước ở các định dạng Base64, Hexadecimal, và Binary sang văn bản rõ (Plaintext)
- **File mã nguồn:** `bai1.py`
 
### Nhiệm vụ 2.2: khảo sát hiện tượng xung đột Hàm băm (MD5 & SHA-1)
- **Mô tả:** thực nghiệm tính chất an toàn phân tích va chạm. Tiến hành so sánh, chỉ ra 6 vị trí byte khác biệt cụ thể giữa 2 thông điệp mẫu nhưng khi băm qua MD5 đều trả về cùng một giá trị duy nhất. Đồng thời, kiểm tra thực tế 2 tệp PDF có nội dung hiển thị trực quan khác hẳn nhau nhưng có mã băm SHA-1 trùng lặp hoàn toàn, từ đó đưa ra kết luận về mức độ mất an toàn của MD5 và SHA-1 ngày nay
- **File mã nguồn:** báo cáo dạng phân tích, kiểm tra trực tiếp qua các tool băm hệ thống và terminal

### Nhiệm vụ 2.3: tạo xung đột MD5 với công cụ md5collgen
- **Mô tả:** sử dụng công cụ md5collgen trên Linux để tạo ra hai tệp tin nhị phân (out1.bin, out2.bin) có nội dung khác biệt nhưng có cùng giá trị băm MD5 dựa trên một tệp tiền tố cho trước. Khảo sát và trả lời câu hỏi về cơ chế tự động chèn các byte đệm (padding) của công cụ khi độ dài tệp tiền tố không phải là bội số của 64 byte
- **File mã nguồn:** sử dụng dòng lệnh Terminal và công cụ md5collgen

### Nhiệm vụ 2.4: xác thực thủ công Chứng chỉ số X.509
- **Mô tả:** kết nối và trích xuất chuỗi chứng chỉ SSL/TLS từ máy chủ từ xa, tách thành chứng chỉ thực thể (c0.pem) và chứng chỉ nhà cấp phát CA (c1.pem). Sử dụng lệnh OpenSSL để lấy cặp khóa công khai (Modulus $n$, Exponent $e$) và định vị vùng dữ liệu được ký (TBSCertificate) bằng lệnh asn1parse. Cuối cùng dùng Python giải mã mã chữ ký RSA để đối chiếu tính toàn vẹn và xác thực thủ công thành công chứng chỉ
- **File mã nguồn:** prefix.txt do mình tự tạo kết hợp các lệnh openssl

## 4. Hướng dẫn chạy chương trình

### Yêu cầu môi trường:
- Môi trường Python 3.x
- Công cụ dòng lệnh OpenSSL (được cài đặt sẵn trên Linux/Git Bash)
- Công cụ tạo xung đột md5collgen
- Thư viện tích hợp sẵn của Python: base64, hashlib

### Thực hiện
1. Đối với file Python thực hiện thuật toán RSA (Nhiệm vụ 2.1):
 ```bash
 python3 bai1.py 
 ```
 (Nhập các tùy chọn hệ thập phân (0) hoặc thập lục phân (1) cùng các giá trị $p, q, e$ theo yêu cầu của chương trình trên màn hình terminal)
 
2. Đối với việc tạo xung đột MD5 bằng công cụ (Nhiệm vụ 2.3):
```bash
# Tạo tệp tiền tố có kích thước mong muốn (ví dụ 64 byte)
echo -n "Prefix data..." > prefix.txt
# Chạy công cụ tạo xung đột
md5collgen -p prefix.txt -o out1.bin out2.bin
# Kiểm tra giá trị băm của 2 file đầu ra
md5sum out1.bin out2.bin
```
3. Đối với quy trình trích xuất và xác thực chứng chỉ số (Nhiệm vụ 2.4):
```bash
# Trích xuất và phân tích cấu trúc chứng chỉ bằng OpenSSL
openssl x509 -in c1.pem -noout -modulus
openssl asn1parse -in c0.pem
# Chạy script Python để giải mã RSA và đối chiếu chuỗi băm xác thực
python3 ify.py
```
