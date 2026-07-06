defmodule Eipex.Adapter.MessageRouter do
  @moduledoc """
  Adapter-side dispatch: Message Router request binary in, response binary
  out. Routes by class code to `Eipex.Adapter.Object` modules. Pure — never
  raises on network input; object crashes map to status 0x1F.
  """

  require Logger

  alias Eipex.Adapter.Config
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.CIP.Path

  @spec dispatch(Config.t(), binary()) :: binary()
  def dispatch(%Config{} = config, request) do
    {response, _extra} = dispatch(config, request, %{})
    response
  end

  @spec dispatch(Config.t(), binary(), map()) :: {binary(), [Eipex.CPF.item()]}
  def dispatch(%Config{} = config, request, extra) do
    case MR.decode_request(request) do
      {:ok, %{service: service, path: path, data: data}} ->
        route(config, service, path, data, extra)

      {:error, _} ->
        {MR.encode_response(0x00, 0x13), []}
    end
  end

  defp route(config, service, path, data, extra) do
    case Path.decode(path) do
      {:ok, [{:class, class} | rest]} ->
        {instance, path_rest} = pop_instance(rest)
        invoke(config, class, service, instance, path_rest, data, extra)

      {:ok, _segments} ->
        {MR.encode_response(service, 0x05), []}

      {:error, _} ->
        {MR.encode_response(service, 0x04), []}
    end
  end

  defp invoke(config, class, service, instance, path_rest, data, extra) do
    case Map.fetch(config.objects, class) do
      {:ok, module} ->
        ctx =
          Map.merge(
            %{
              config: config,
              store: config.store,
              handler: config.handler,
              session: self(),
              connections: config.connections
            },
            extra
          )

        try do
          case module.handle_service(service, instance, path_rest, data, ctx) do
            {:reply, reply_data} ->
              {MR.encode_response(service, 0x00, data: reply_data), []}

            {:reply, reply_data, extra_cpf} ->
              {MR.encode_response(service, 0x00, data: reply_data), extra_cpf}

            {:raw, response} ->
              {response, []}

            {:error, status, extended} ->
              {MR.encode_response(service, status, extended: extended), []}
          end
        rescue
          exception ->
            Logger.error("CIP object #{inspect(module)} crashed: #{Exception.message(exception)}")

            {MR.encode_response(service, 0x1F), []}
        end

      :error ->
        {MR.encode_response(service, 0x05), []}
    end
  end

  defp pop_instance([{:instance, instance} | rest]), do: {instance, rest}
  defp pop_instance(rest), do: {0, rest}
end
