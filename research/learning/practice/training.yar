rule TrainingPair {
    strings:
        $marker = "training-marker"
        $word = "harbor" fullword
    condition:
        all of them
}
