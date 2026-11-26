# metricflow-self-host

Mã nguồn MetricFlow (bộ dịch chỉ tiêu của dbt) giữ trong GitLab của nhóm, để đọc, rà bảo mật và sửa khi cần cho kho dữ liệu `insur-dwh`.

- **Gốc:** tag [`v0.214.0`](https://github.com/dbt-labs/metricflow/tree/v0.214.0) của `dbt-labs/metricflow`, commit `a379ff0`. Gồm `metricflow`, `metricflow_semantics`, `metricflow_semantic_interfaces` và `dbt-metricflow` (lệnh `mf`). Giấy phép Apache-2.0 ([LICENSE](LICENSE)).
- **README gốc:** [README.upstream.md](README.upstream.md).
- Repo không nối với GitHub: không có remote, không có lịch sử của upstream.

## Khác bản gốc

| Thay đổi | File |
|---|---|
| Bỏ CI của GitHub và pre-commit của upstream | `.github/`, `.pre-commit-config.yaml` (đã xoá) |
| Bỏ bộ database thử có mật khẩu viết sẵn | `local-data-warehouses/` (đã xoá) |
| Bỏ toàn bộ test và fixture kết nối mẫu; nhóm không chạy test của upstream | `tests_metricflow/`, `tests_metricflow_semantics/`, `tests_metricflow_semantic_interfaces/`, `dbt-metricflow/tests_dbt_metricflow/` (đã xoá) |
| Mật khẩu mẫu của các môi trường test hatch để trống | `pyproject.toml`, 4 dòng `MF_SQL_ENGINE_PASSWORD` |
| README này; README gốc đổi tên | `README.md`, `README.upstream.md` |
| Pre-commit riêng: quét bí mật, cú pháp, chặn commit vào `production`. GitLab không chạy pipeline nào | `.pre-commit-config.yaml`, `scripts/security/scan_secrets.py` (chép nguyên từ `dagster-self-host`), `.gitlab-ci.yml` |

Chưa sửa dòng mã Python nào của MetricFlow.

## Dùng trong kho

- Định nghĩa chỉ tiêu của kho nằm ở repo `dbt`: `models/starmart/semantic/semantic_models.yml`, sinh từ `semantic/catalog.yml` (`make semantic`).
- Chạy: cài gói `dbt-metricflow` cùng bản (`pip install "dbt-metricflow~=0.16"`, kéo theo `metricflow` 0.214.0), rồi trong repo `dbt`: `dbt parse`, `mf query --metrics dtps --group-by metric_time__month`.
- Bản tự host chỉ có dòng lệnh `mf` và thư viện Python, không có API hay giao diện; trợ lý `tro-ly-ai` gọi nó qua Python.

## Kiểm tra: pre-commit trên laptop

```bash
uv tool install pre-commit      # một lần trên máy
pre-commit install              # một lần trong repo
```

| Hook | Làm gì |
|---|---|
| `secret-scan`, `detect-private-key`, `forbid-env-files` | chặn mật khẩu, token, khoá, IP nội bộ, file `.env`. File đã có ở HEAD chỉ quét dòng thêm / sửa |
| `check-yaml`, `check-toml`, `check-merge-conflict`, `check-added-large-files` | cú pháp, dấu xung đột, file trên 1 MB |
| `no-commit-to-branch` | không commit thẳng vào `production` |
| `shell-scripts` | `bash -n` cho `*.sh` |

`python3 -B scripts/security/scan_secrets.py --all` còn báo vài chục chỗ của upstream: mã băm trong `.changes/`, tên khoá trong mã. Đã rà, không có bí mật.

## Nâng bản

Chưa làm lần nào. Cách dự kiến: tải cây file của tag mới, chép đè lên repo (trừ các file ở mục "Khác bản gốc"), xoá lại đúng các thư mục trong bảng, chạy `scan_secrets.py --all`, commit bằng `git commit --no-verify` vì commit có cả nghìn file của upstream.
