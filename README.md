# QR 정품/가품 판별 시연 시스템 (Flask + Railway)

최초 1회 스캔 시 정품 페이지, 2회 이상 스캔 시 가품 의심 페이지를 보여주는 시연용 Flask 프로젝트입니다.

## 기능
- 관리자 페이지에서 QR 생성
- QR마다 난수 파라미터 자동 생성
- 1회 스캔: 정품 페이지
- 2회 이상 스캔: 가품/재사용 의심 페이지
- SQLite 기반 스캔 이력 저장
- Railway 배포 지원

## 로컬 실행
```bash
pip install -r requirements.txt
python app.py
```

## Railway 배포
1. GitHub에 전체 파일 업로드
2. Railway에서 **Deploy from GitHub Repo** 선택
3. 배포 후 `Settings > Networking` 에서 도메인 생성
4. 필요 시 Variables에 아래 추가
   - `BASE_URL=https://생성된도메인`
5. 재배포 후 `/admin` 접속

## 주요 경로
- `/admin` : QR 생성
- `/history` : 생성된 QR 및 스캔 이력 확인
- `/scan/<token>?r=<난수>` : QR 스캔 진입 경로

## 참고
- SQLite 파일(`data.db`)은 컨테이너 재배포 시 초기화될 수 있습니다.
- 시연용으로는 충분하지만, 운영용은 PostgreSQL 전환을 권장합니다.


추가 기능
- /stats : QR별 통계 목록
- /stats/<id> : 각 QR별 스캔 시간, IP, 브라우저/OS, 위치 허용 좌표 조회
