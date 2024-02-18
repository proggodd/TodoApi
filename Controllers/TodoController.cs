using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApplication.Data;
using TodoApplication.Models;

namespace TodoApplication.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class TodoController : ControllerBase
    {
        private readonly ApiDbContext _context;
        public TodoController(ApiDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult> GetItems()
        {
            var items = await _context.Items.ToListAsync();
            return Ok(items);
        }

        [HttpPost]
        public async Task<IActionResult> CreateItem(ItemData item)
        {
            if (ModelState.IsValid)
            {
                await _context.Items.AddAsync(item);
                await _context.SaveChangesAsync();
                return CreatedAtAction("GetItem", new { item.Id }, item);
            }
            return new JsonResult("something went wrong") { StatusCode = 500 };

        }
        [HttpGet("{id}")]
        public async Task<IActionResult> GetItem(int id)
        {

            var item = await _context.Items.SingleOrDefaultAsync(x => x.Id == id);

            if (item == null)
            {
                return NotFound();
            }
            return Ok(item);
        }
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateItem(int id, ItemData item)
        {
            if (id != item.Id)
            {
                return BadRequest();
            }

            var existingItem = await _context.Items.FirstOrDefaultAsync(x => x.Id == id);
            if (existingItem == null)
            {
                return NotFound();
            }

            existingItem.Title = item.Title;
            existingItem.Description = item.Description;
            existingItem.Done = item.Done;

            await _context.SaveChangesAsync();
            return NoContent();
        }
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteItem(int id)
        {
            var item = _context.Items.SingleOrDefault(x => x.Id == id);
            if (item == null) 
            {
                return NotFound();
            }

            _context.Items.Remove(item);
            await _context.SaveChangesAsync();

            return Ok(item);
        }
    }
}
