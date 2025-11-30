import xgboost as xgb

model = xgb.Booster()
model.load_model("model.json")
model.save_model("model.ubj")
