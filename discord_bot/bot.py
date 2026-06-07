"""
KeyAuth Discord Bot - Manage license keys from Discord

Setup:
1. Install: pip install discord.py requests python-dotenv
2. Set DISCORD_BOT_TOKEN in .env
3. Run: python bot.py

Commands (admin only):
  !genkey [count] [days]  - Generate license keys
  !keyinfo <key>          - Check license info
  !ban <key>              - Ban a license
  !unban <key>            - Unban a license
  !resethwid <key>        - Reset HWID lock
  !stats                  - Server status
  !shutdown               - Stop the bot
"""
import discord
from discord.ext import commands
from config import DISCORD_BOT_TOKEN

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


@bot.event
async def on_ready():
    print(f"✅ Logged in as {bot.user}")
    print(f"   Bot ID: {bot.user.id}")
    print(f"   Servers: {len(bot.guilds)}")
    await bot.change_presence(activity=discord.Game(name="!help | KeyAuth"))


@bot.command(name="help")
async def custom_help(ctx):
    embed = discord.Embed(
        title="KeyAuth Bot Commands",
        description="All admin commands:",
        color=discord.Color.blue()
    )
    embed.add_field(name="!genkey [count] [days]", value="Generate license keys", inline=False)
    embed.add_field(name="!keyinfo <key>", value="Look up license info", inline=False)
    embed.add_field(name="!ban <key>", value="Ban a license", inline=False)
    embed.add_field(name="!unban <key>", value="Unban a license", inline=False)
    embed.add_field(name="!resethwid <key>", value="Reset HWID on a key", inline=False)
    embed.add_field(name="!stats", value="Show API server status", inline=False)
    embed.add_field(name="!shutdown", value="Stop the bot", inline=False)
    await ctx.send(embed=embed)


async def load_extensions():
    await bot.load_extension("cogs.keys")
    await bot.load_extension("cogs.admin")


if __name__ == "__main__":
    import asyncio
    asyncio.run(load_extensions())
    bot.run(DISCORD_BOT_TOKEN)
