package job

import (
	"time"

	"x-ui/logger"
	"x-ui/web/service"
)

type WarpIPJob struct {
	settingService service.SettingService
	warpService    *service.WarpService
	xrayService    service.XrayService
}

func NewWarpIPJob() *WarpIPJob {
	return &WarpIPJob{warpService: service.NewWarpService()}
}

func (j *WarpIPJob) Run() {
	interval, err := j.settingService.GetWarpUpdateInterval()
	if err != nil || interval <= 0 {
		return
	}
	lastUpdate, _ := j.settingService.GetWarpLastUpdate()
	now := time.Now().Unix()
	if lastUpdate == 0 {
		_ = j.settingService.SetWarpLastUpdate(now)
		return
	}
	elapsedSeconds := now - lastUpdate
	if elapsedSeconds < 0 || elapsedSeconds/(24*60*60) < int64(interval) {
		return
	}
	if _, err := j.warpService.ChangeWarpIP(); err != nil {
		logger.Warning("scheduled WARP IP update failed: ", err)
		return
	}
	_ = j.settingService.SetWarpLastUpdate(now)
	j.xrayService.SetToNeedRestart()
	logger.Info("scheduled WARP IP update completed")
}
