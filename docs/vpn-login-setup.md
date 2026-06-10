# Ẩn IP khi login Claude Code (VPN / SOCKS) — Hướng 1

## Vì sao cần cái này

Claude Cloak chỉ chuyển hướng traffic tới **`api.anthropic.com`** qua proxy (đặt
`ANTHROPIC_BASE_URL`). Nhưng khi bạn chạy `claude` và nó bắt **login**, luồng đó là
**OAuth qua trình duyệt** tới `claude.ai` / `console.anthropic.com`, cộng thêm bước
**token-exchange** do CLI gọi. Những request này **không** tuân theo
`ANTHROPIC_BASE_URL`, nên chúng đi thẳng từ máy bạn → **lộ IP thật ngay lúc login**,
kể cả khi bạn đã chạy Server Mode.

> Nói ngắn gọn: **proxy che được API, KHÔNG che được login.** Để che IP lúc login,
> phải xử lý ở **tầng mạng** — đó là VPN/SOCKS.

Điểm mấu chốt để làm **đúng**: VPN phải ở chế độ **full-tunnel** (định tuyến *toàn
bộ* traffic của máy qua VM), vì luồng login gồm nhiều endpoint khác nhau
(`claude.ai`, `console.anthropic.com`, callback localhost, token-exchange...). Nếu chỉ
route chọn lọc theo domain thì rất dễ sót và vẫn lộ IP. Full-tunnel che được tất cả,
không cần đoán endpoint nào.

---

## Kiến trúc khuyến nghị (VPN + Server Mode)

```
┌── Máy A ──┐                                  ┌──────────── VM ────────────┐
│ Claude CLI │  == WireGuard tunnel (UDP) ==>  │  WireGuard server (wg0)     │
│ + browser  │   mọi traffic đi qua đây        │  10.8.0.1                   │
└────────────┘                                  │                            │
┌── Máy B ──┐                                  │  Claude Cloak proxy :9999   │
│ Claude CLI │  =============================>  │  (DEPLOY_MODE=server)       │
└────────────┘                                  └──────────────┬─────────────┘
                                                               │ IP công cộng của VM
                                                               ▼
                                          claude.ai · console.anthropic.com · api.anthropic.com
```

- **WireGuard (full-tunnel)** lo phần **IP**: login browser, token-exchange, và mọi
  thứ khác đều đi ra từ **IP công cộng của VM**.
- **Claude Cloak Server Mode** lo phần **fingerprint thiết bị** + **API** + dashboard
  tập trung.
- Anthropic chỉ thấy **một IP** (IP của VM) cho **cả login lẫn API**, từ mọi máy.

Dùng chung một VM cho cả WireGuard và proxy là hợp lý nhất.

---

## Phần 1 — Dựng WireGuard server trên VM (Ubuntu/Debian)

> Yêu cầu: VM có IP công cộng tĩnh, quyền `sudo`. Mở **UDP 51820** trên firewall /
> cloud security group.

### 1.1. Cài đặt

```bash
sudo apt update && sudo apt install -y wireguard
```

### 1.2. Sinh khóa cho server

```bash
umask 077
wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key
```

### 1.3. Bật IP forwarding (để VM định tuyến traffic của client ra Internet)

```bash
echo 'net.ipv4.ip_forward = 1'  | sudo tee /etc/sysctl.d/99-wireguard.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-wireguard.conf
sudo sysctl -p /etc/sysctl.d/99-wireguard.conf
```

### 1.4. Tạo `/etc/wireguard/wg0.conf`

> Thay `eth0` bằng tên interface ra Internet của VM (kiểm tra bằng
> `ip route show default` → cột `dev`).

```ini
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = <NỘI_DUNG server_private.key>
# NAT: cho traffic của client đi ra ngoài qua IP công cộng của VM
PostUp   = iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# === Mỗi máy client là một [Peer] — thêm bên dưới ===
# [Peer]
# PublicKey = <public key của client>
# AllowedIPs = 10.8.0.2/32
```

### 1.5. Khởi động và bật chạy lúc boot

```bash
sudo systemctl enable --now wg-quick@wg0
sudo wg show          # kiểm tra interface đã lên
```

### 1.6. Mở firewall

```bash
sudo ufw allow 51820/udp
# Nếu dùng cloud: mở thêm UDP 51820 trong security group
```

---

## Phần 2 — Cấu hình từng máy client

### 2.1. Cài WireGuard

- **Windows / macOS**: tải app WireGuard chính chủ (wireguard.com/install).
- **Linux**: `sudo apt install wireguard`.

### 2.2. Sinh khóa cho client

App WireGuard (Win/macOS) tự sinh khi bạn tạo "Empty tunnel". Trên Linux:

```bash
umask 077
wg genkey | tee client_private.key | wg pubkey | tee client_public.key
```

### 2.3. File cấu hình client (full-tunnel)

```ini
[Interface]
PrivateKey = <client_private.key>
Address = 10.8.0.2/32          # đổi .2 → .3, .4... cho từng máy
DNS = 1.1.1.1                  # tránh DNS leak — bắt buộc khi full-tunnel

[Peer]
PublicKey = <server_public.key>
Endpoint = <IP_CÔNG_CỘNG_VM>:51820
AllowedIPs = 0.0.0.0/0, ::/0   # ⬅ FULL-TUNNEL: route TẤT CẢ qua VM
PersistentKeepalive = 25
```

> `AllowedIPs = 0.0.0.0/0, ::/0` chính là chỗ quyết định "đúng" — nó đẩy **mọi**
> traffic (login browser + token-exchange + API) qua VM. Nếu để CIDR hẹp thì login
> vẫn lộ IP.

### 2.4. Khai báo client lên server

Trên VM, thêm vào `/etc/wireguard/wg0.conf`:

```ini
[Peer]
PublicKey = <client_public.key của máy này>
AllowedIPs = 10.8.0.2/32
```

Rồi nạp lại không cần ngắt kết nối các peer khác:

```bash
sudo wg syncconf wg0 <(wg-quick strip wg0)
```

### 2.5. Bật tunnel và kiểm tra

Bật tunnel trong app (hoặc `sudo wg-quick up wg0` trên Linux), rồi **xác minh IP đã
đổi thành IP của VM**:

```bash
curl https://api.ipify.org      # phải in ra IP CÔNG CỘNG CỦA VM
```

Nếu lệnh này in ra IP của VM → toàn bộ traffic (gồm cả login) đã đi qua VM. ✅

---

## Phần 3 — Ghép với Claude Cloak Server Mode

Khi đã có VPN, cho client nói chuyện với proxy **qua IP nội bộ trong tunnel** để gọn
và an toàn:

1. **Trên VM** (`client/.env`):
   ```env
   DEPLOY_MODE=server
   LOCAL_HOST=0.0.0.0
   ALLOWED_IPS=10.8.0.0/24        # chỉ cho các peer trong VPN dùng proxy
   ```
   Chạy `./start-server.sh` (hoặc `start-server.bat`).

2. **Trên mỗi máy client** — trỏ Claude Code vào IP VPN của VM:
   ```bash
   ./setup-remote.sh http://10.8.0.1:9999 phong      # macOS / Linux
   setup-remote.bat  http://10.8.0.1:9999 phong      # Windows
   ```

3. **Login**: chạy `claude`, làm theo luồng login như bình thường. Vì tunnel đang
   bật, browser mở `claude.ai` cũng xuất phát từ IP của VM → **không lộ IP thật**.

Kết quả: Anthropic thấy **một IP duy nhất** (VM) cho **cả login lẫn API**, và một
**fingerprint thiết bị duy nhất** từ mọi máy.

> Ghi chú: nếu dùng full-tunnel, traffic tới `api.anthropic.com` thực ra đã đi ra từ
> IP VM rồi (kể cả ở Local Mode). Server Mode vẫn đáng dùng vì lo phần **fingerprint
> dùng chung** (khỏi copy `.env` qua từng máy) + **dashboard / quota tập trung**.

---

## Phương án nhẹ (SSH SOCKS) — không cần cài VPN

Nếu chỉ muốn thử nhanh và không muốn cài WireGuard, có thể dùng SSH dynamic SOCKS:

```bash
ssh -N -D 1080 user@<IP_VM>      # mở SOCKS5 proxy ở localhost:1080
```

Rồi cấu hình **trình duyệt** dùng SOCKS5 `127.0.0.1:1080` (Firefox: Settings →
Network → SOCKS v5, bật "Proxy DNS when using SOCKS v5" để tránh DNS leak). Khi login,
chọn mở link trong trình duyệt đã cấu hình SOCKS đó.

**Hạn chế cần biết:**
- Chỉ **browser** được route qua SOCKS. Bước **token-exchange do CLI gọi** có thể
  **vẫn lộ IP thật** nếu nó không đi qua proxy này → kém chắc chắn hơn full-tunnel.
- Phải nhớ bật SSH tunnel mỗi lần, và đảm bảo đúng trình duyệt được dùng cho callback.

👉 Vì vậy SSH SOCKS chỉ nên dùng để thử nhanh. Muốn **chắc chắn không lộ IP khi
login**, hãy dùng **WireGuard full-tunnel** ở trên.

---

## Checklist kiểm tra "đã đúng"

- [ ] `curl https://api.ipify.org` trên client (khi bật tunnel) trả về **IP của VM**.
- [ ] Tắt tunnel → chạy lại, IP đổi về IP thật (xác nhận tunnel thực sự có tác dụng).
- [ ] DNS không leak: dùng `DNS = 1.1.1.1` (hoặc DNS của VM) trong config client.
- [ ] Login `claude` **trong khi tunnel đang bật**, không phải sau khi tắt.
- [ ] `ALLOWED_IPS` trên VM gồm dải VPN `10.8.0.0/24`; client trỏ
      `ANTHROPIC_BASE_URL` vào `http://10.8.0.1:9999/...`.

## Lưu ý an toàn

- IP datacenter của VM đôi khi bị các dịch vụ đánh giá rủi ro cao hơn IP dân dụng.
  Đây là đánh đổi cố hữu: bạn ẩn IP cá nhân nhưng gom mọi thứ vào một IP.
- VPN che **IP**, không che **fingerprint** — đó là việc của Claude Cloak. Cần cả hai.
- Giữ `server_private.key` và `.env` của VM như credential: ai đọc được là chiếm được
  cả pool.
