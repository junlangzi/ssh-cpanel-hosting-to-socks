codeBash

```
pip install PyQt5 psutil asyncssh cryptography
```


### 1. Tổng Quan

**Hosting proxy** là chương trình dùng hosting cpanel làm proxy cho máy tính để có thể giúp chúng ta vào mạng mượt mà hơn mỗi khi cá mập cắn cáp.
Chương trình được viết bằng python,  để chạy chương trình hãy cài đặt các gói cần thiết sau:

### 2. Các Tính Năng Nổi Bật

#### A. Chức năng cốt lõi (Core)

1.  **Chuyển đổi SSH sang SOCKS5:** Tạo một server SOCKS5 cục bộ (ví dụ: 127.0.0.1:10800) và chuyển tiếp dữ liệu qua đường hầm SSH (SSH Tunneling).
    
2.  **Hai chế độ hoạt động:**
    
    -   **Single Server:** Kết nối tới 1 VPS duy nhất.
        
    -   **Multi Server (Smart Load Balancing):** Kết nối đồng thời nhiều VPS. Ứng dụng sử dụng thuật toán thông minh (Least Connections) để tự động điều hướng traffic vào server đang rảnh nhất, giúp tăng tốc độ và độ ổn định.
        
3.  **System Proxy Manager:** Tự động bật/tắt Proxy của hệ thống Windows (Internet Settings). Có cơ chế an toàn (atexit) để tự tắt proxy khi ứng dụng bị tắt đột ngột, tránh mất mạng cho người dùng.
    

#### B. Bảo mật (Security)

1.  **Mã hóa cấu hình (Hardware-ID Binding):**
    
    -   Sử dụng thư viện cryptography để mã hóa mật khẩu lưu trong file settings.ini.
        
    -   **Điểm hay:** Khóa giải mã được tạo dựa trên **UUID của máy tính** (uuid.getnode()). Điều này có nghĩa là nếu ai đó copy file settings.ini của bạn sang máy khác, họ **không thể giải mã** để lấy trộm mật khẩu SSH.
        
2.  **Ẩn mật khẩu:** Giao diện có nút "con mắt" để hiện/ẩn mật khẩu và tự động che khi nhập liệu.
    

#### C. Tiện ích mạng & Giám sát

1.  **Đo tốc độ Real-time:** Hiển thị tốc độ Upload/Download và tổng dung lượng đã dùng.
    
2.  **Kiểm tra Ping & Jitter:** Gửi gói tin qua đường hầm Proxy để đo độ trễ thực tế tới Google DNS (8.8.8.8).
    
3.  **GeoIP Checker:** Tự động kiểm tra IP sau khi kết nối, hiển thị Quốc gia, Thành phố và **Cờ quốc gia** tương ứng. Hỗ trợ nhiều nguồn check (ip-api, reallyfreegeoip...) với khả năng tùy chỉnh độ ưu tiên.
    

#### D. Giao diện (UI/UX)

1.  **Quản lý lịch sử:** Lưu danh sách các server đã dùng, hỗ trợ thêm/sửa/xóa tiện lợi.
    
2.  **Tùy biến giao diện:** Cho phép chỉnh Font chữ, Cỡ chữ, Màu nền, Màu chữ ngay trong tab Cài đặt.
    
3.  **System Tray:** Thu nhỏ xuống khay hệ thống, hiển thị Tooltip trạng thái kết nối khi di chuột vào icon.
    
4.  **Tự động cài Dependency:** Khi chạy lần đầu, nếu thiếu thư viện, chương trình sẽ tự động hỏi và chạy lệnh pip install để cài đặt.
    

----------

### 3. Cách Thức Hoạt Động (Technical Flow)

1.  **Khởi động:**
    
    -   Kiểm tra thư viện -> Nạp cấu hình -> Giải mã dữ liệu cũ -> Hiển thị GUI.
        
    -   Đảm bảo Proxy hệ thống đang tắt để tránh xung đột.
        
2.  **Khi nhấn "KẾT NỐI" (Start):**
    
    -   Chương trình khởi tạo luồng NetworkEngine (dùng QThread).
        
    -   Bên trong luồng này, nó tạo một **Event Loop** của asyncio.
        
    -   **Kết nối SSH:** Sử dụng thư viện asyncssh để kết nối bất đồng bộ tới (các) server đích.
        
    -   **Tạo SOCKS5 Server:** Mở port local (ví dụ 10800) để lắng nghe kết nối từ trình duyệt/ứng dụng.
        
    -   **Routing:** Khi có request từ người dùng:
        
        -   Nếu là chế độ **Multi**: Thuật toán get_next_backend sẽ tìm port local của kết nối SSH nào đang gánh ít request nhất để chuyển dữ liệu vào đó.
            
    -   **Cập nhật Registry:** Nếu người dùng chọn "System Proxy", nó dùng winreg để set proxy cho Windows.
        
3.  **Giám sát:**
    
    -   NetworkChecker định kỳ tạo socket đi qua proxy local để đo Ping.
        
    -   psutil đo lưu lượng mạng tổng của máy để tính tốc độ Up/Down.
        
4.  **Kết thúc:**
    
    -   Đóng các socket, hủy luồng, khôi phục Registry Windows về mặc định.
        

----------

### 4. Lệnh Cài Đặt (Installation)

Mặc dù trong code đã có đoạn check_and_install_dependencies để tự động cài, nhưng để đảm bảo môi trường ổn định nhất, bạn nên cài thủ công bằng lệnh sau trong CMD hoặc Terminal:

codeBash

```
pip install PyQt5 psutil asyncssh cryptography
```

**Chi tiết các gói:**

-   PyQt5: Thư viện giao diện đồ họa.
    
-   psutil: Lấy thông tin hệ thống (tốc độ mạng).
    
-   asyncssh: Thư viện SSH bất đồng bộ (nhanh và hiệu quả hơn paramiko cho việc tạo tunnel).
    
-   cryptography: Dùng để mã hóa mật khẩu trong file cấu hình.
    

### 5. Lưu Ý Khi Chạy

-   **Hệ điều hành:** Code này được thiết kế tối ưu cho **Windows** (do sử dụng winreg và ctypes.windll để set proxy và hiển thị thông báo hệ thống). Nếu chạy trên Linux/macOS sẽ cần sửa lại phần SystemProxyManager.
    
-   **Quyền Admin:** Đôi khi việc set System Proxy yêu cầu quyền Administrator, nếu thấy không đổi IP hệ thống, hãy thử chạy "Run as Administrator".
    
-   **Python Version:** Nên sử dụng Python 3.8 trở lên để hỗ trợ tốt nhất cho asyncio.

Ngoài ra bạn có thể sử dụng app  RocketTunnel để kết nối với hosting trên điện thoại để làm vpn:

Android link: [RocketTunnel - Apps on Google Play](https://play.google.com/store/apps/details?id=com.hypertunnel.android&hl=en)
IOS link: [‎RocketTunnel App - App Store](https://apps.apple.com/us/app/rockettunnel/id6478808249)

**Ảnh Demo:**

![enter image description here](https://raw.githubusercontent.com/junlangzi/ssh-cpanel-hosting-to-socks/refs/heads/main/demo/1.png)

![enter image description here](https://raw.githubusercontent.com/junlangzi/ssh-cpanel-hosting-to-socks/refs/heads/main/demo/2.png)
![enter image description here](https://raw.githubusercontent.com/junlangzi/ssh-cpanel-hosting-to-socks/refs/heads/main/demo/3.png)

