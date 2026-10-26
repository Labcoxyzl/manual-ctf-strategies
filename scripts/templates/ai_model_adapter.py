"""Copy this file and connect the challenge's model wrapper before executing it."""


def load_model(path):
    raise NotImplementedError('connect the challenge model loader')


def load_input(path):
    raise NotImplementedError('return a floating torch.Tensor with exact challenge preprocessing')


def loss(model, tensor, target):
    raise NotImplementedError('return one torch scalar to maximize for the chosen target')


def reset(seed):
    raise NotImplementedError('return observation, hidden state, previous action')


def policy_step(observation, previous_action, hidden):
    raise NotImplementedError('return auxiliary vector, next hidden state')


def env_step(action):
    raise NotImplementedError('apply one action and return the next observation')
